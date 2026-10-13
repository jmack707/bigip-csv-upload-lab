import pytest

from app.multipart_strict import MultipartError, check_filename, extract_single_file

B = "----labboundary"
CT = f"multipart/form-data; boundary={B}"


def body(parts: list[tuple[str, bytes]], close: bool = True) -> bytes:
    out = b""
    for headers, data in parts:
        out += f"--{B}\r\n{headers}\r\n\r\n".encode() + data + b"\r\n"
    if close:
        out += f"--{B}--\r\n".encode()
    return out


def file_part(name="file", filename="a.csv", ctype="text/csv", data=b"a,b\n1,2\n"):
    h = f'Content-Disposition: form-data; name="{name}"; filename="{filename}"'
    if ctype:
        h += f"\r\nContent-Type: {ctype}"
    return (h, data)


def test_single_good_part():
    fp = extract_single_file(CT, body([file_part()]), "file")
    assert (fp.field_name, fp.filename, fp.content_type) == ("file", "a.csv", "text/csv")
    assert fp.data == b"a,b\n1,2\n"


def test_not_multipart():
    with pytest.raises(MultipartError) as ei:
        extract_single_file("application/json", b"{}", "file")
    assert ei.value.reason_code == "NOT_MULTIPART"


def test_missing_boundary():
    with pytest.raises(MultipartError) as ei:
        extract_single_file("multipart/form-data", b"", "file")
    assert ei.value.reason_code == "MALFORMED_MULTIPART"


def test_truncated_body():
    with pytest.raises(MultipartError) as ei:
        extract_single_file(CT, body([file_part()], close=False), "file")
    assert ei.value.reason_code == "MALFORMED_MULTIPART"


def test_garbage_body():
    with pytest.raises(MultipartError) as ei:
        extract_single_file(CT, b"this is not multipart at all", "file")
    assert ei.value.reason_code == "MALFORMED_MULTIPART"


def test_wrong_field_name():
    with pytest.raises(MultipartError) as ei:
        extract_single_file(CT, body([file_part(name="upload")]), "file")
    assert ei.value.reason_code == "UNEXPECTED_PART"


def test_missing_file_part():
    with pytest.raises(MultipartError) as ei:
        extract_single_file(CT, body([('Content-Disposition: form-data; name="note"', b"hi")]), "file")
    assert ei.value.reason_code == "UNEXPECTED_PART"


def test_second_file_part():
    with pytest.raises(MultipartError) as ei:
        extract_single_file(CT, body([file_part(), file_part(filename="b.csv")]), "file")
    assert ei.value.reason_code == "UNEXPECTED_PART"


def test_field_without_filename():
    with pytest.raises(MultipartError) as ei:
        extract_single_file(CT, body([('Content-Disposition: form-data; name="file"', b"a,b\n")]), "file")
    assert ei.value.reason_code == "FILENAME_MISSING"


def test_rfc5987_filename_star_rejected():
    h = "Content-Disposition: form-data; name=\"file\"; filename*=UTF-8''a.csv\r\nContent-Type: text/csv"
    with pytest.raises(MultipartError) as ei:
        extract_single_file(CT, body([(h, b"a,b\n")]), "file")
    assert ei.value.reason_code == "FILENAME_ENCODING"


def test_non_ascii_filename_rejected():
    h = 'Content-Disposition: form-data; name="file"; filename="d\xe9.csv"\r\nContent-Type: text/csv'
    with pytest.raises(MultipartError) as ei:
        extract_single_file(CT, body([(h.encode("latin-1").decode("latin-1"), b"a,b\n")]), "file")
    assert ei.value.reason_code == "FILENAME_ENCODING"


@pytest.mark.parametrize("name,code", [
    ("a.txt", "FILENAME_EXTENSION"),
    ("a.csv.exe", "FILENAME_EXTENSION"),
    ("a.CSV", "FILENAME_EXTENSION"),
    ("report.2024.csv", "FILENAME_EXTENSION"),
    ("my file.csv", "FILENAME_EXTENSION"),
    (".csv", "FILENAME_EXTENSION"),
    ("../a.csv", "FILENAME_PATH"),
    ("dir/a.csv", "FILENAME_PATH"),
    ("C:\\a.csv", "FILENAME_PATH"),
    ("", "FILENAME_MISSING"),
])
def test_filename_policy_rejects(name, code):
    with pytest.raises(MultipartError) as ei:
        check_filename(name)
    assert ei.value.reason_code == code


def test_filename_policy_accepts():
    assert check_filename("Report_2024-q1.csv") == "Report_2024-q1.csv"
