from copy import deepcopy

import pytest

from csk_registry import signing
from csk_registry.bundle import export_bundle, import_bundle
from csk_registry.store import Store
from test_registry import _body, _client


def body(version):
    result = _body()
    result['schema_version'] = version
    if version == 2:
        result['hash_version'] = 2
    return result


def publish(client, key, token, record):
    return client.post('/v1/records', json=key.sign_record(record),
                       headers={'Authorization': f'Bearer {token}'})


@pytest.mark.parametrize('version', [1, 2])
def test_http_matching_is_version_scoped(tmp_path, version):
    client, _, token = _client(tmp_path)
    auditor = client.app.state.auditor_key
    record = body(version)
    assert publish(client, auditor, token, record).status_code == 201
    for identity in [False, True]:
        query = {'content_sha256': record['content_sha256']}
        if identity:
            query.update(source_identity=record['source_identity'], commit=record['commit'])
        for requested in [1, 2]:
            response = client.get('/v1/records', params={**query, 'hash_version': requested})
            assert response.status_code == 200
            assert len(response.json()['records']) == int(requested == version)
        assert len(client.get('/v1/records', params=query).json()['records']) == int(version == 1)


def test_projection_and_pagination_keep_both_versions(tmp_path):
    client, _, token = _client(tmp_path)
    auditor = client.app.state.auditor_key
    for version in [1, 2]:
        assert publish(client, auditor, token, body(version)).status_code == 201
    query = {k: body(1)[k] for k in ['source_identity', 'commit']}
    query['limit'] = 1
    first = client.get('/v1/records', params=query).json()
    assert first['records'][0]['schema_version'] == 1
    second = client.get('/v1/records', params={**query, 'cursor': first['next_cursor']}).json()
    assert second['records'][0]['hash_version'] == 2
    assert second['next_cursor'] is None


@pytest.mark.parametrize('schema,framing', [(1, 1), (1, 2), (2, None), (2, 1), (2, True), (2, '2'), (2, 3)])
def test_publication_refuses_version_disagreement(tmp_path, schema, framing):
    client, _, token = _client(tmp_path)
    record = body(schema)
    record.pop('hash_version', None)
    if framing is not None:
        record['hash_version'] = framing
    response = publish(client, client.app.state.auditor_key, token, record)
    assert response.status_code == 400
    assert response.json()['error']['code'] == 'invalid_record'
    assert 'hash_version_mismatch' in response.json()['error']['message']
    assert client.get('/v1/snapshot').json()['log_size'] == 0
    store = Store(tmp_path / 'direct.db')
    with pytest.raises(ValueError, match='hash_version_mismatch'):
        store.append(signing.generate_key().sign_record(record), created_at='2026-09-30T00:00:00Z')


@pytest.mark.parametrize('query', [{'hash_version': '2'}, {'hash_version': '3', 'content_sha256': 'sha256:' + 'a'*64}, {'hash_version': 'true', 'content_sha256': 'sha256:' + 'a'*64}])
def test_invalid_version_query(tmp_path, query):
    client, _, _ = _client(tmp_path)
    query.update(source_identity=body(1)['source_identity'], commit=body(1)['commit'])
    assert client.get('/v1/records', params=query).status_code == 400


def test_mixed_bundle_roundtrip_and_refusals(tmp_path):
    key, local = signing.generate_key(), signing.generate_key()
    upstream = Store(tmp_path / 'upstream.db')
    for version in [1, 2]:
        upstream.append(key.sign_record(body(version)), created_at='2026-09-30T00:00:00Z')
    bundle = export_bundle(upstream, key)
    assert bundle['schema_version'] == 2
    assert bundle['snapshot']['schema_version'] == 1
    downstream = Store(tmp_path / 'downstream.db')
    assert import_bundle(downstream, local, bundle, upstream_public_key=key.public_pinned) == 2
    assert import_bundle(downstream, local, bundle, upstream_public_key=key.public_pinned) == 0
    reopened = Store(tmp_path / 'downstream.db')
    for version in [1, 2]:
        records = reopened.records_for(content_sha256=body(1)['content_sha256'], hash_version=version)
        assert len(records) == 1
        assert records[0].get('hash_version', 1) == version
        assert signing.verify_signed(local.public_pinned, records[0])
    for mutation in ['envelope', 'record', 'missing_key']:
        bad = deepcopy(bundle)
        if mutation == 'envelope':
            bad['schema_version'] = 1
        elif mutation == 'record':
            bad['records'][1]['hash_version'] = 1
            bad['records'][1] = key.sign_record(bad['records'][1])
        else:
            del bad['public_key']
        fresh = Store(tmp_path / f'{mutation}.db')
        with pytest.raises(ValueError):
            import_bundle(fresh, local, bad, upstream_public_key=key.public_pinned)
        assert fresh.log_entries() == []


def test_version_is_bound_to_cursor_and_snapshot(tmp_path):
    client, _, token = _client(tmp_path)
    auditor = client.app.state.auditor_key
    for name in ['a', 'b']:
        record = {**body(2), 'name': name}
        assert publish(client, auditor, token, record).status_code == 201
    query = {'content_sha256': body(2)['content_sha256'], 'hash_version': 2, 'limit': 1}
    first = client.get('/v1/records', params=query).json()
    assert first['next_cursor']
    record = {**body(2), 'name': 'c'}
    assert publish(client, auditor, token, record).status_code == 201
    second = client.get('/v1/records', params={**query, 'cursor': first['next_cursor']}).json()
    assert second['records'][0]['name'] == 'b'
    assert second['next_cursor'] is None
    assert second['boundary'] == first['boundary']
    assert client.get('/v1/records', params={**query, 'hash_version': 1, 'cursor': first['next_cursor']}).status_code == 404
