from __future__ import annotations

import ctypes
import os
import stat
from ctypes import wintypes
from pathlib import Path
from typing import Any


_TOKEN_QUERY = 0x0008
_TOKEN_USER_CLASS = 1
_ERROR_INSUFFICIENT_BUFFER = 122
_SDDL_REVISION_1 = 1
_SE_FILE_OBJECT = 1
_DACL_SECURITY_INFORMATION = 0x00000004
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_SE_DACL_PROTECTED = 0x1000
_ACCESS_ALLOWED_ACE_TYPE = 0
_OBJECT_INHERIT_ACE = 0x01
_CONTAINER_INHERIT_ACE = 0x02
_FILE_ALL_ACCESS = 0x001F01FF


class _SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


class _TOKEN_USER(ctypes.Structure):
    _fields_ = [("User", _SID_AND_ATTRIBUTES)]


class _ACL(ctypes.Structure):
    _fields_ = [
        ("AclRevision", wintypes.BYTE),
        ("Sbz1", wintypes.BYTE),
        ("AclSize", wintypes.WORD),
        ("AceCount", wintypes.WORD),
        ("Sbz2", wintypes.WORD),
    ]


class _ACE_HEADER(ctypes.Structure):
    _fields_ = [
        ("AceType", wintypes.BYTE),
        ("AceFlags", wintypes.BYTE),
        ("AceSize", wintypes.WORD),
    ]


class _ACCESS_ALLOWED_ACE(ctypes.Structure):
    _fields_ = [
        ("Header", _ACE_HEADER),
        ("Mask", wintypes.DWORD),
        ("SidStart", wintypes.DWORD),
    ]


_ADVAPI32: Any | None = None
_KERNEL32: Any | None = None


def protect_private_directory(path: Path) -> None:
    """Make an existing directory accessible only to the service identity."""
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"private state path {path} is not a directory")
    if os.name == "nt":
        _set_windows_private_acl(path, directory=True)
        if not _windows_private_acl_is_valid(path, directory=True):
            raise PermissionError(f"could not verify private directory ACL for {path}")
        return
    path.chmod(0o700)
    if stat.S_IMODE(path.lstat().st_mode) != 0o700:
        raise PermissionError(f"could not establish mode 0700 for {path}")


def protect_private_file(path: Path) -> None:
    """Make an existing regular file accessible only to the service identity."""
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"private state path {path} is not a regular file")
    if os.name == "nt":
        _set_windows_private_acl(path, directory=False)
        if not _windows_private_acl_is_valid(path, directory=False):
            raise PermissionError(f"could not verify private file ACL for {path}")
        return
    path.chmod(0o600)
    if stat.S_IMODE(path.lstat().st_mode) != 0o600:
        raise PermissionError(f"could not establish mode 0600 for {path}")


def require_private_file(path: Path) -> None:
    """Reject a private-state file whose type or access controls are unsafe."""
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"private state path {path} is not a regular file")
    if os.name == "nt":
        if not _windows_private_acl_is_valid(path, directory=False):
            raise PermissionError(f"private file ACL is too broad for {path}")
        return
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise PermissionError(f"private file permissions are too broad for {path}")


def private_directory_permissions_enforced(path: Path) -> bool:
    try:
        metadata = path.lstat()
        if not stat.S_ISDIR(metadata.st_mode):
            return False
        if os.name == "nt":
            return _windows_private_acl_is_valid(path, directory=True)
        return stat.S_IMODE(metadata.st_mode) == 0o700
    except (OSError, ValueError):
        return False


def private_file_permissions_enforced(path: Path) -> bool:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            return False
        if os.name == "nt":
            return _windows_private_acl_is_valid(path, directory=False)
        return stat.S_IMODE(metadata.st_mode) & 0o077 == 0
    except (OSError, ValueError):
        return False


def _windows_apis() -> tuple[Any, Any]:
    global _ADVAPI32, _KERNEL32
    if os.name != "nt":
        raise RuntimeError("Windows ACL APIs are unavailable on this platform")
    if _ADVAPI32 is not None and _KERNEL32 is not None:
        return _ADVAPI32, _KERNEL32

    win_dll: Any = getattr(ctypes, "WinDLL")
    advapi32: Any = win_dll("advapi32", use_last_error=True)
    kernel32: Any = win_dll("kernel32", use_last_error=True)

    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    advapi32.GetSecurityDescriptorDacl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    advapi32.GetSecurityDescriptorControl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
    advapi32.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.GetAce.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetAce.restype = wintypes.BOOL

    _ADVAPI32 = advapi32
    _KERNEL32 = kernel32
    return advapi32, kernel32


def _current_user_sid() -> str:
    advapi32, kernel32 = _windows_apis()
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)):
        raise _windows_error("OpenProcessToken")
    try:
        size = wintypes.DWORD()
        advapi32.GetTokenInformation(
            token,
            _TOKEN_USER_CLASS,
            None,
            0,
            ctypes.byref(size),
        )
        if size.value == 0 or _last_error() != _ERROR_INSUFFICIENT_BUFFER:
            raise _windows_error("GetTokenInformation(size)")
        buffer = ctypes.create_string_buffer(size.value)
        if not advapi32.GetTokenInformation(
            token,
            _TOKEN_USER_CLASS,
            buffer,
            size,
            ctypes.byref(size),
        ):
            raise _windows_error("GetTokenInformation")
        token_user = ctypes.cast(buffer, ctypes.POINTER(_TOKEN_USER)).contents
        return _sid_string(token_user.User.Sid)
    finally:
        kernel32.CloseHandle(token)


def _sid_string(sid: ctypes.c_void_p) -> str:
    advapi32, kernel32 = _windows_apis()
    value = wintypes.LPWSTR()
    if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(value)):
        raise _windows_error("ConvertSidToStringSidW")
    try:
        if value.value is None:
            raise OSError("ConvertSidToStringSidW returned an empty SID")
        return value.value
    finally:
        kernel32.LocalFree(ctypes.cast(value, ctypes.c_void_p))


def _set_windows_private_acl(path: Path, *, directory: bool) -> None:
    advapi32, kernel32 = _windows_apis()
    sid = _current_user_sid()
    inheritance = "OICI" if directory else ""
    sddl = f"D:P(A;{inheritance};FA;;;{sid})"
    descriptor = ctypes.c_void_p()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl,
        _SDDL_REVISION_1,
        ctypes.byref(descriptor),
        None,
    ):
        raise _windows_error("ConvertStringSecurityDescriptorToSecurityDescriptorW")
    try:
        present = wintypes.BOOL()
        defaulted = wintypes.BOOL()
        dacl = ctypes.c_void_p()
        if not advapi32.GetSecurityDescriptorDacl(
            descriptor,
            ctypes.byref(present),
            ctypes.byref(dacl),
            ctypes.byref(defaulted),
        ):
            raise _windows_error("GetSecurityDescriptorDacl")
        if not present.value or not dacl.value:
            raise OSError("generated private security descriptor has no DACL")
        result = advapi32.SetNamedSecurityInfoW(
            str(path),
            _SE_FILE_OBJECT,
            _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            dacl,
            None,
        )
        if result != 0:
            raise OSError(result, f"SetNamedSecurityInfoW failed for {path}")
    finally:
        kernel32.LocalFree(descriptor)


def _windows_private_acl_is_valid(path: Path, *, directory: bool) -> bool:
    advapi32, kernel32 = _windows_apis()
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    result = advapi32.GetNamedSecurityInfoW(
        str(path),
        _SE_FILE_OBJECT,
        _DACL_SECURITY_INFORMATION,
        None,
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if result != 0:
        raise OSError(result, f"GetNamedSecurityInfoW failed for {path}")
    try:
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        if not advapi32.GetSecurityDescriptorControl(
            descriptor,
            ctypes.byref(control),
            ctypes.byref(revision),
        ):
            raise _windows_error("GetSecurityDescriptorControl")
        if not control.value & _SE_DACL_PROTECTED or not dacl.value:
            return False
        acl = ctypes.cast(dacl, ctypes.POINTER(_ACL)).contents
        if acl.AceCount != 1:
            return False
        ace_pointer = ctypes.c_void_p()
        if not advapi32.GetAce(dacl, 0, ctypes.byref(ace_pointer)):
            raise _windows_error("GetAce")
        ace = ctypes.cast(ace_pointer, ctypes.POINTER(_ACCESS_ALLOWED_ACE)).contents
        expected_flags = _OBJECT_INHERIT_ACE | _CONTAINER_INHERIT_ACE if directory else 0
        if (
            ace.Header.AceType != _ACCESS_ALLOWED_ACE_TYPE
            or ace.Header.AceFlags != expected_flags
            or ace.Mask != _FILE_ALL_ACCESS
        ):
            return False
        sid_address = ace_pointer.value
        if sid_address is None:
            return False
        sid_pointer = ctypes.c_void_p(sid_address + _ACCESS_ALLOWED_ACE.SidStart.offset)
        return _sid_string(sid_pointer) == _current_user_sid()
    finally:
        kernel32.LocalFree(descriptor)


def _last_error() -> int:
    get_last_error: Any = getattr(ctypes, "get_last_error")
    return int(get_last_error())


def _windows_error(operation: str) -> OSError:
    code = _last_error()
    return OSError(code, f"{operation} failed with Windows error {code}")
