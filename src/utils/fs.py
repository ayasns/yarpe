from sc import sc
from structure import Structure
from utils.conversion import u64_to_i64
from utils.etc import alloc


__all__ = [
    "stat_file",
    "file_exists",
    "read_file_data",
    "write_file_data",
]


STAT_STRUCT = Structure(
    [
        ("st_dev", 4),
        ("st_ino", 8),
        ("st_mode", 2),
        ("st_nlink", 2),
        ("st_uid", 4),
        ("st_gid", 4),
        ("st_rdev", 8),
        ("st_atime", 8),
        ("st_atime_nsec", 8),
        ("st_mtime", 8),
        ("st_mtime_nsec", 8),
        ("st_ctime", 8),
        ("st_ctime_nsec", 8),
        ("st_size", 8),
        ("st_blocks", 8),
        ("st_blksize", 4),
        ("st_flags", 4),
        ("st_gen", 4),
        ("st_lspare", 4),
        ("st_birthtime", 8),
        ("st_birthtime_nsec", 8),
        ("reserved2", 16),
    ]
)


def stat_file(path):
    stat = STAT_STRUCT.create()
    ret = u64_to_i64(sc.syscalls.stat(path, stat))
    if ret < 0:
        raise Exception(
            "stat failed with errno %d\n%s"
            % (sc.syscalls.stat.errno, sc.syscalls.stat.get_error_string())
        )

    return stat


def file_exists(path):
    try:
        stat_file(path)
        return True
    except:
        return False


def read_file_data(path):
    fd = u64_to_i64(sc.syscalls.open(path, 0, 0))
    if fd < 0:
        raise Exception(
            "open failed with errno %d\n%s"
            % (sc.syscalls.open.errno, sc.syscalls.open.get_error_string())
        )

    data = b""
    read_size = -1
    buf = alloc(4096)
    while read_size != 0:
        read_size = u64_to_i64(sc.syscalls.read(fd, buf, 4096))
        data += buf[:read_size]
        if read_size < 0:
            raise Exception(
                "read failed with errno %d\n%s"
                % (sc.syscalls.read.errno, sc.syscalls.read.get_error_string())
            )

    sc.syscalls.close(fd)
    return data


def write_file_data(path, data):
    fd = u64_to_i64(
        sc.syscalls.open(path, 65, 0o666)
    )  # O_WRONLY | O_CREAT | O_TRUNC, 0666
    if fd < 0:
        raise Exception(
            "open failed with errno %d\n%s"
            % (sc.syscalls.open.errno, sc.syscalls.open.get_error_string())
        )

    total_written = 0
    data_len = len(data)
    while total_written < data_len:
        to_write = data[total_written : total_written + 4096]
        write_size = u64_to_i64(sc.syscalls.write(fd, to_write, len(to_write)))
        if write_size < 0:
            raise Exception(
                "write failed with errno %d\n%s"
                % (sc.syscalls.write.errno, sc.syscalls.write.get_error_string())
            )
        total_written += write_size

    sc.syscalls.close(fd)
