#!/usr/bin/env bash
# Generate every test input under test/files/. Idempotent. No live malware:
# the only "malicious" sample is the EICAR test string.
set -eu   # no pipefail: `yes | head` legitimately ends with SIGPIPE
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/files"
mkdir -p "$OUT"
cd "$OUT"

w() { printf '%b' "$2" > "$1"; }   # w <file> <printf-escaped content>

# ---- accepted -------------------------------------------------------------
w ok_basic.csv            'id,name,city\n1,alice,Oslo\n2,bob,Lima\n'
w ok_quoted.csv           'id,name\n1,"alice"\n2,"bob"\n'
w ok_embedded_comma.csv   'id,address\n1,"1 Main St, Springfield"\n2,"2 High St, Bath"\n'
w ok_embedded_newline.csv 'id,note\n1,"line one\nline two"\n2,"single"\n'
w ok_semicolon.csv        'id;name;amount\n1;alice;10\n2;bob;20\n'
w ok_tab.csv              'id\tname\tamount\n1\talice\t10\n2\tbob\t20\n'
printf 'id,name\n1,Zo\xc3\xab \xc3\x85ngstr\xc3\xb6m\n2,Jos\xc3\xa9\n' > ok_utf8_accents.csv
w ok_negative_numbers.csv 'id,delta,price\n1,-5,+3.20\n2,-0.5,7\n'
w ok_phone_numbers.csv    'name,phone\nbob,555-0100\nann,(555) 010-0100\ncy,1-555-010-0100\n'
w ok_trailing_blank.csv   'id,name\n1,alice\n\n\n'       # accepted only with IGNORE_TRAILING_BLANK_LINES=true
w ok_crlf.csv             'id,name\r\n1,alice\r\n2,bob\r\n'

# ---- rejected by BIG-IP (request-level) -----------------------------------
w bad_ext.txt             'id,name\n1,ext-txt\n'
w bad_double_ext.csv.exe  'id,name\n1,double-ext\n'
# A minimal PE (MZ) header renamed .csv: binary executable detection sample.
printf 'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00' > bad_pe_renamed.csv
head -c 100 /dev/zero >> bad_pe_renamed.csv
printf 'PE\x00\x00\x4c\x01\x01\x00' >> bad_pe_renamed.csv
# A minimal ELF header renamed .csv.
printf '\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00\x01\x00\x00\x00' > bad_elf_renamed.csv
head -c 64 /dev/zero >> bad_elf_renamed.csv
# Oversized file: 1 MiB + 1 byte of valid CSV (request stays under 1.25 MiB).
{ printf 'id,value\n'; yes '1,abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuv' | head -c 1048577; } > bad_oversized_file.csv
# Oversized request: ~1.4 MiB of valid CSV (request exceeds 1.25 MiB).
{ printf 'id,value\n'; yes '1,abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuv' | head -c 1468000; } > bad_oversized_request.csv
# Malformed multipart body sent raw with a multipart Content-Type.
w bad_malformed_body.bin  '--xx\r\nContent-Disposition: form-data; name="file"; filename="a.csv"\r\n\r\nid,name\n1,a\n'

# ---- rejected by the validator --------------------------------------------
: > bad_empty.csv
w bad_json.csv            '{"id": 1, "name": "alice"}\n'
w bad_html.csv            '<html><body><p>hello</p></body></html>\n'
printf 'id,name\n1,\xff\xfe\xfa\n' > bad_invalid_utf8.csv
printf 'id,name\n1,alice\n' | iconv -f UTF-8 -t UTF-16 > bad_utf16.csv
w bad_unclosed_quote.csv  'id,name\n1,"alice\n'
w bad_quote_in_field.csv  'id,name\n1,al"ice\n'
w bad_missing_column.csv  'id,name,city\n1,alice\n'
w bad_extra_column.csv    'id,name\n1,alice,Oslo\n'
w bad_blank_between.csv   'id,name\n1,alice\n\n2,bob\n'
w bad_pipe_delim.csv      'id|name\n1|alice\n'
w bad_formula_eq.csv      'id,name\n1,=1+1\n'
w bad_formula_at.csv      'id,name\n1,@SUM(A1:A2)\n'
w bad_formula_plus.csv    'id,name\n1,+cmd|'"'"' /C calc'"'"'!A0\n'
w bad_formula_minus.csv   'id,name\n1,-2+3\n'
w bad_formula_spaces.csv  'id,name\n1,   =1+1\n'
w bad_formula_quoted.csv  'id,name\n1,"=1+1"\n'
w bad_markup.csv          'id,name\n1,<script>alert(1)</script>\n'
w bad_javascript.csv      'id,link\n1,javascript:alert(1)\n'

# ---- antivirus --------------------------------------------------------------
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > av_eicar.csv
# The same string inside an otherwise valid CSV: passes the validator, so only the antivirus can stop it.
printf 'id,note\n1,X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\n' > av_eicar_in_csv.csv
w ok_ops.csv              'id,name\n1,ops-probe\n'

ls -l "$OUT" | awk '{print $5, $9}' | column -t
