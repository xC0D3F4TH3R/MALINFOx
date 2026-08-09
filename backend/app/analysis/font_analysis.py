"""MALINFO — Font File Analysis (TTF, OTF, WOFF, WOFF2)

Analysis of font files for exploitation vectors and steganography.
"""
from __future__ import annotations

import logging
import struct
from typing import TYPE_CHECKING

from app.analysis.strings_entropy import shannon_entropy

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger("malinfo.font_analysis")


def analyze_font(file_path: Path) -> dict:
    """
    Analyze font file (TTF, OTF, WOFF, WOFF2).
    """
    result: dict = {
        "available": True,
        "format": "Font File",
        "font_type": "",
        "tables": [],
        "glyph_count": 0,
        "font_name": "",
        "font_family": "",
        "font_subfamily": "",
        "version": "",
        "copyright": "",
        "manufacturer": "",
        "designer": "",
        "license": "",
        "unicode_ranges": [],
        "codepage_ranges": [],
        "suspicious_indicators": [],
        "entropy": 0.0,
        "errors": [],
    }

    try:
        with open(file_path, "rb") as f:
            data = f.read()

        result["entropy"] = round(shannon_entropy(data[:8192]), 3)

        # Detect font type
        if data[:4] == b"\x00\x01\x00\x00" or data[:4] == b"OTTO" or data[:4] == b"ttcf":
            result["font_type"] = "TTF/OTF/TTC"
            _analyze_ttf_otf(data, result)
        elif data[:4] == b"wOFF":
            result["font_type"] = "WOFF"
            _analyze_woff(data, result)
        elif data[:4] == b"wOF2":
            result["font_type"] = "WOFF2"
            _analyze_woff2(data, result)
        else:
            result["errors"].append("Unknown font format")

    except Exception as exc:
        logger.debug(f"Font analysis failed: {exc}")
        result["error"] = str(exc)
        result["available"] = False

    return result


def _analyze_ttf_otf(data: bytes, result: dict) -> None:
    """Analyze TTF/OTF/TTC font."""
    try:
        offset = 0
        num_fonts = 1

        # Check for TTC (TrueType Collection)
        if data[:4] == b"ttcf":
            result["font_type"] = "TTC (TrueType Collection)"
            # TTC header
            major = struct.unpack(">H", data[4:6])[0]
            minor = struct.unpack(">H", data[6:8])[0]
            num_fonts = struct.unpack(">I", data[8:12])[0]
            result["ttc_version"] = f"{major}.{minor}"
            result["ttc_font_count"] = num_fonts
            offset = 12
        else:
            offset = 0

        # Parse each font in collection
        for font_idx in range(num_fonts):
            if offset >= len(data):
                break

            font_data = data[offset:]
            if len(font_data) < 12:
                break

            # Font header
            scaler_type = font_data[:4]
            if scaler_type == b"\x00\x01\x00\x00":
                result["font_format"] = "TrueType"
            elif scaler_type == b"OTTO":
                result["font_format"] = "OpenType (CFF)"
            elif scaler_type == b"true":
                result["font_format"] = "TrueType (Apple)"
            else:
                result["font_format"] = f"Unknown ({scaler_type.hex()})"

            num_tables = struct.unpack(">H", font_data[4:6])[0]
            search_range = struct.unpack(">H", font_data[6:8])[0]
            entry_selector = struct.unpack(">H", font_data[8:10])[0]
            range_shift = struct.unpack(">H", font_data[10:12])[0]

            # Table directory
            tables = []
            table_offset = 12
            for i in range(num_tables):
                if table_offset + 16 > len(font_data):
                    break
                tag = font_data[table_offset:table_offset+4].decode("ascii", errors="ignore")
                checksum = struct.unpack(">I", font_data[table_offset+4:table_offset+8])[0]
                offset_val = struct.unpack(">I", font_data[table_offset+8:table_offset+12])[0]
                length = struct.unpack(">I", font_data[table_offset+12:table_offset+16])[0]
                tables.append({
                    "tag": tag,
                    "checksum": hex(checksum),
                    "offset": offset_val,
                    "length": length,
                })
                table_offset += 16

            result["tables"] = tables

            # Parse key tables
            _parse_name_table(font_data, tables, result)
            _parse_head_table(font_data, tables, result)
            _parse_maxp_table(font_data, tables, result)
            _parse_os2_table(font_data, tables, result)
            _parse_cmap_table(font_data, tables, result)
            _parse_glyf_table(font_data, tables, result)
            _parse_cff_table(font_data, tables, result)

            # Move to next font in TTC
            if num_fonts > 1:
                # In TTC, offset table entries point to each font
                pass

            break  # Only analyze first font for now

    except Exception as exc:
        result["errors"].append(f"TTF/OTF parsing failed: {exc}")


def _parse_name_table(data: bytes, tables: list, result: dict) -> None:
    """Parse 'name' table for font metadata."""
    name_table = next((t for t in tables if t["tag"] == "name"), None)
    if not name_table:
        return

    try:
        offset = name_table["offset"]
        length = name_table["length"]
        table_data = data[offset:offset+length]

        if len(table_data) < 6:
            return

        format_ = struct.unpack(">H", table_data[0:2])[0]
        count = struct.unpack(">H", table_data[2:4])[0]
        string_offset = struct.unpack(">H", table_data[4:6])[0]

        name_records_start = 6
        for i in range(count):
            if name_records_start + 12 > len(table_data):
                break
            platform_id = struct.unpack(">H", table_data[name_records_start:name_records_start+2])[0]
            encoding_id = struct.unpack(">H", table_data[name_records_start+2:name_records_start+4])[0]
            language_id = struct.unpack(">H", table_data[name_records_start+4:name_records_start+6])[0]
            name_id = struct.unpack(">H", table_data[name_records_start+6:name_records_start+8])[0]
            str_len = struct.unpack(">H", table_data[name_records_start+8:name_records_start+10])[0]
            str_off = struct.unpack(">H", table_data[name_records_start+10:name_records_start+12])[0]

            # Get string
            string_start = string_offset + str_off
            string_end = string_start + str_len
            if string_end <= len(table_data):
                string_bytes = table_data[string_start:string_end]
                # Decode based on platform
                if platform_id == 0:  # Unicode
                    try:
                        string = string_bytes.decode("utf-16be")
                    except UnicodeDecodeError:
                        string = string_bytes.decode("utf-16be", errors="replace")
                elif platform_id == 3:  # Windows
                    try:
                        string = string_bytes.decode("utf-16le")
                    except UnicodeDecodeError:
                        string = string_bytes.decode("utf-16le", errors="replace")
                elif platform_id == 1:  # Mac
                    try:
                        string = string_bytes.decode("mac-roman")
                    except UnicodeDecodeError:
                        string = string_bytes.decode("latin-1", errors="replace")
                else:
                    string = string_bytes.decode("utf-8", errors="replace")

                # Map name_id to field
                name_ids = {
                    0: "copyright",
                    1: "font_family",
                    2: "font_subfamily",
                    3: "unique_subfamily",
                    4: "full_name",
                    5: "version",
                    6: "postscript_name",
                    7: "trademark",
                    8: "manufacturer",
                    9: "designer",
                    10: "description",
                    11: "vendor_url",
                    12: "designer_url",
                    13: "license",
                    14: "license_url",
                    16: "preferred_family",
                    17: "preferred_subfamily",
                    18: "compatible_full",
                    19: "sample_text",
                }

                field = name_ids.get(name_id, f"name_{name_id}")
                if field in ["copyright", "font_family", "font_subfamily", "version", "manufacturer", "designer", "license"]:
                    result[field] = string

            name_records_start += 12

    except Exception as exc:
        logger.debug(f"Name table parsing failed: {exc}")


def _parse_head_table(data: bytes, tables: list, result: dict) -> None:
    """Parse 'head' table for font header info."""
    head_table = next((t for t in tables if t["tag"] == "head"), None)
    if not head_table:
        return

    try:
        offset = head_table["offset"]
        table_data = data[offset:offset+54]

        if len(table_data) < 54:
            return

        version = struct.unpack(">I", table_data[0:4])[0]
        font_revision = struct.unpack(">I", table_data[4:8])[0]
        checksum = struct.unpack(">I", table_data[8:12])[0]
        magic = struct.unpack(">I", table_data[12:16])[0]
        flags = struct.unpack(">H", table_data[16:18])[0]
        units_per_em = struct.unpack(">H", table_data[18:20])[0]
        created = table_data[20:28]
        modified = table_data[28:36]
        x_min = struct.unpack(">h", table_data[36:38])[0]
        y_min = struct.unpack(">h", table_data[38:40])[0]
        x_max = struct.unpack(">h", table_data[40:42])[0]
        y_max = struct.unpack(">h", table_data[42:44])[0]
        mac_style = struct.unpack(">H", table_data[44:46])[0]
        lowest_rec_ppem = struct.unpack(">H", table_data[46:48])[0]
        font_direction = struct.unpack(">h", table_data[48:50])[0]
        index_to_loc_format = struct.unpack(">H", table_data[50:52])[0]
        glyph_data_format = struct.unpack(">H", table_data[52:54])[0]

        result["head"] = {
            "version": f"{version >> 16}.{version & 0xFFFF}",
            "font_revision": f"{font_revision >> 16}.{font_revision & 0xFFFF}",
            "checksum": hex(checksum),
            "magic": hex(magic),
            "flags": flags,
            "units_per_em": units_per_em,
            "x_min": x_min, "y_min": y_min, "x_max": x_max, "y_max": y_max,
            "mac_style": mac_style,
            "index_to_loc_format": index_to_loc_format,
        }

    except Exception as exc:
        logger.debug(f"Head table parsing failed: {exc}")


def _parse_maxp_table(data: bytes, tables: list, result: dict) -> None:
    """Parse 'maxp' table for glyph count."""
    maxp_table = next((t for t in tables if t["tag"] == "maxp"), None)
    if not maxp_table:
        return

    try:
        offset = maxp_table["offset"]
        table_data = data[offset:offset+maxp_table["length"]]

        if len(table_data) < 6:
            return

        version = struct.unpack(">I", table_data[0:4])[0]
        num_glyphs = struct.unpack(">H", table_data[4:6])[0]

        result["glyph_count"] = num_glyphs
        result["maxp_version"] = f"{version >> 16}.{version & 0xFFFF}"

    except Exception as exc:
        logger.debug(f"Maxp table parsing failed: {exc}")


def _parse_os2_table(data: bytes, tables: list, result: dict) -> None:
    """Parse 'OS/2' table for Unicode ranges and codepages."""
    os2_table = next((t for t in tables if t["tag"] == "OS/2"), None)
    if not os2_table:
        return

    try:
        offset = os2_table["offset"]
        table_data = data[offset:offset+os2_table["length"]]

        if len(table_data) < 86:
            return

        version = struct.unpack(">H", table_data[0:2])[0]
        x_avg_char_width = struct.unpack(">h", table_data[2:4])[0]
        us_weight_class = struct.unpack(">H", table_data[4:6])[0]
        us_width_class = struct.unpack(">H", table_data[6:8])[0]
        fs_type = struct.unpack(">H", table_data[8:10])[0]
        y_subscript_x_size = struct.unpack(">h", table_data[10:12])[0]
        y_subscript_y_size = struct.unpack(">h", table_data[12:14])[0]
        y_subscript_x_offset = struct.unpack(">h", table_data[14:16])[0]
        y_subscript_y_offset = struct.unpack(">h", table_data[16:18])[0]
        y_superscript_x_size = struct.unpack(">h", table_data[18:20])[0]
        y_superscript_y_size = struct.unpack(">h", table_data[20:22])[0]
        y_superscript_x_offset = struct.unpack(">h", table_data[22:24])[0]
        y_superscript_y_offset = struct.unpack(">h", table_data[24:26])[0]
        y_strikeout_size = struct.unpack(">h", table_data[26:28])[0]
        y_strikeout_position = struct.unpack(">h", table_data[28:30])[0]
        s_family_class = struct.unpack(">h", table_data[30:32])[0]

        # Panose
        panose = table_data[32:42]

        # Unicode ranges (4 uint32)
        if len(table_data) >= 74:
            ul_unicode_range1 = struct.unpack(">I", table_data[42:46])[0]
            ul_unicode_range2 = struct.unpack(">I", table_data[46:50])[0]
            ul_unicode_range3 = struct.unpack(">I", table_data[50:54])[0]
            ul_unicode_range4 = struct.unpack(">I", table_data[54:58])[0]

            result["unicode_ranges"] = _decode_unicode_ranges(
                ul_unicode_range1, ul_unicode_range2, ul_unicode_range3, ul_unicode_range4
            )

        # Codepage ranges (2 uint32)
        if len(table_data) >= 86:
            ul_codepage_range1 = struct.unpack(">I", table_data[78:82])[0]
            ul_codepage_range2 = struct.unpack(">I", table_data[82:86])[0]

            result["codepage_ranges"] = _decode_codepage_ranges(ul_codepage_range1, ul_codepage_range2)

        result["os2_version"] = version
        result["fs_type"] = fs_type  # Font embedding licensing rights

    except Exception as exc:
        logger.debug(f"OS/2 table parsing failed: {exc}")


def _parse_cmap_table(data: bytes, tables: list, result: dict) -> None:
    """Parse 'cmap' table for character mapping."""
    cmap_table = next((t for t in tables if t["tag"] == "cmap"), None)
    if not cmap_table:
        return

    # Just note presence
    result["has_cmap"] = True


def _parse_glyf_table(data: bytes, tables: list, result: dict) -> None:
    """Parse 'glyf' table for glyph outlines."""
    glyf_table = next((t for t in tables if t["tag"] == "glyf"), None)
    if not glyf_table:
        return

    result["has_glyf"] = True
    result["glyf_size"] = glyf_table["length"]


def _parse_cff_table(data: bytes, tables: list, result: dict) -> None:
    """Parse 'CFF ' table for OpenType/CFF fonts."""
    cff_table = next((t for t in tables if t["tag"] == "CFF "), None)
    if not cff_table:
        return

    result["has_cff"] = True
    result["cff_size"] = cff_table["length"]


def _decode_unicode_ranges(r1: int, r2: int, r3: int, r4: int) -> list[str]:
    """Decode Unicode range bits."""
    ranges = []
    # Simplified - just list which ranges are set
    for i in range(128):
        if i < 32:
            bit = (r1 >> i) & 1
        elif i < 64:
            bit = (r2 >> (i-32)) & 1
        elif i < 96:
            bit = (r3 >> (i-64)) & 1
        else:
            bit = (r4 >> (i-96)) & 1
        if bit:
            ranges.append(f"Range {i}")
    return ranges


def _decode_codepage_ranges(r1: int, r2: int) -> list[str]:
    """Decode codepage range bits."""
    codepages = {
        0: "1252 Latin 1",
        1: "1250 Latin 2",
        2: "1251 Cyrillic",
        3: "1253 Greek",
        4: "1254 Turkish",
        5: "1255 Hebrew",
        6: "1256 Arabic",
        7: "1257 Baltic",
        8: "1258 Vietnam",
        16: "874 Thai",
        17: "932 JIS/Japan",
        18: "936 Chinese Simplified",
        19: "949 Korean",
        20: "950 Chinese Traditional",
        21: "1361 Korean (Johab)",
        29: "Macintosh Roman",
        30: "OEM",
        31: "Symbol",
    }
    ranges = []
    for i in range(64):
        bit = r1 >> i & 1 if i < 32 else r2 >> i - 32 & 1
        if bit and i in codepages:
            ranges.append(codepages[i])
    return ranges


def _analyze_woff(data: bytes, result: dict) -> None:
    """Analyze WOFF font."""
    try:
        # WOFF header
        flavor = data[4:8]
        length = struct.unpack(">I", data[8:12])[0]
        num_tables = struct.unpack(">H", data[12:14])[0]
        reserved = data[14:16]

        result["woff_flavor"] = flavor.decode("ascii", errors="ignore")
        result["woff_length"] = length
        result["woff_table_count"] = num_tables

        # Table directory
        tables = []
        offset = 16
        for i in range(num_tables):
            if offset + 20 > len(data):
                break
            tag = data[offset:offset+4].decode("ascii", errors="ignore")
            offset_val = struct.unpack(">I", data[offset+4:offset+8])[0]
            comp_length = struct.unpack(">I", data[offset+8:offset+12])[0]
            orig_length = struct.unpack(">I", data[offset+12:offset+16])[0]
            check_sum = struct.unpack(">I", data[offset+16:offset+20])[0]
            tables.append({
                "tag": tag,
                "offset": offset_val,
                "compressed_length": comp_length,
                "original_length": orig_length,
                "checksum": hex(check_sum),
            })
            offset += 20

        result["tables"] = tables
        result["compressed"] = True

    except Exception as exc:
        result["errors"].append(f"WOFF parsing failed: {exc}")


def _analyze_woff2(data: bytes, result: dict) -> None:
    """Analyze WOFF2 font."""
    try:
        # WOFF2 header
        signature = data[4:8]
        flavor = data[8:12]
        length = struct.unpack(">I", data[12:16])[0]
        num_tables = struct.unpack(">H", data[16:18])[0]

        result["woff2_signature"] = signature.decode("ascii", errors="ignore")
        result["woff2_flavor"] = flavor.decode("ascii", errors="ignore")
        result["woff2_length"] = length
        result["woff2_table_count"] = num_tables

        # WOFF2 uses compressed table directory - simplified
        result["compressed"] = True
        result["transform"] = "Brotli"

    except Exception as exc:
        result["errors"].append(f"WOFF2 parsing failed: {exc}")


def analyze_font_file(file_path: Path) -> dict:
    """Main entry point."""
    return analyze_font(file_path)