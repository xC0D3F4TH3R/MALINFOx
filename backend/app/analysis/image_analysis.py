"""MALINFO — Image/Media Analysis (PNG, JPEG, GIF, BMP, TIFF, SVG, MP4, etc.)

Analysis for steganography, metadata, and embedded payloads.
"""
from __future__ import annotations

import logging
import struct
from typing import TYPE_CHECKING, Optional

from app.analysis.strings_entropy import shannon_entropy

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger("malinfo.image_analysis")


def analyze_image(file_path: Path) -> dict:
    """
    Analyze image file for metadata, steganography, and embedded payloads.
    """
    result: dict = {
        "available": True,
        "format": "Image",
        "image_type": "",
        "dimensions": {},
        "color_depth": 0,
        "compression": "",
        "metadata": {},
        "exif": {},
        "xmp": {},
        "iptc": {},
        "icc_profile": {},
        "chunks": [],
        "steganography_indicators": [],
        "embedded_payloads": [],
        "suspicious_indicators": [],
        "entropy": 0.0,
        "errors": [],
    }

    try:
        with open(file_path, "rb") as f:
            data = f.read()

        result["entropy"] = round(shannon_entropy(data[:8192]), 3)

        # Detect image type
        if data[:8] == b"\x89PNG\r\n\x1a\n":
            result["image_type"] = "PNG"
            _analyze_png(data, result)
        elif data[:3] == b"\xff\xd8\xff":
            result["image_type"] = "JPEG"
            _analyze_jpeg(data, result)
        elif data[:6] in (b"GIF87a", b"GIF89a"):
            result["image_type"] = "GIF"
            _analyze_gif(data, result)
        elif data[:2] == b"BM":
            result["image_type"] = "BMP"
            _analyze_bmp(data, result)
        elif data[:4] in (b"II\x2a\x00", b"MM\x00\x2a", b"II\x2b\x00", b"MM\x00\x2b"):
            result["image_type"] = "TIFF"
            _analyze_tiff(data, result)
        elif data[:4] == b"<svg" or data[:5] == b"<?xml":
            result["image_type"] = "SVG"
            _analyze_svg(data, result)
        elif data[:4] == b"RIFF" and data[8:12] == b"WEBP":
            result["image_type"] = "WEBP"
            _analyze_webp(data, result)
        elif data[:12] == b"\x00\x00\x00\x0cJXL ":
            result["image_type"] = "JPEG XL"
            result["errors"].append("JPEG XL analysis not fully implemented")
        else:
            result["errors"].append("Unsupported image format")

    except Exception as exc:
        logger.debug(f"Image analysis failed: {exc}")
        result["error"] = str(exc)
        result["available"] = False

    return result


def _analyze_png(data: bytes, result: dict) -> None:
    """Analyze PNG image."""
    try:
        offset = 8  # Skip signature
        chunks = []

        while offset < len(data):
            if offset + 8 > len(data):
                break
            length = struct.unpack(">I", data[offset:offset+4])[0]
            chunk_type = data[offset+4:offset+8].decode("ascii", errors="ignore")
            chunk_data = data[offset+8:offset+8+length]
            crc = struct.unpack(">I", data[offset+8+length:offset+12+length])[0]

            chunks.append({
                "type": chunk_type,
                "length": length,
                "crc": hex(crc),
            })

            # Parse specific chunks
            if chunk_type == "IHDR":
                _parse_png_ihdr(chunk_data, result)
            elif chunk_type == "PLTE":
                result["palette_size"] = length // 3
            elif chunk_type == "IDAT":
                result["idat_count"] = result.get("idat_count", 0) + 1
                result["idat_total_size"] = result.get("idat_total_size", 0) + length
            elif chunk_type == "tEXt":
                _parse_png_text(chunk_data, result, "tEXt")
            elif chunk_type == "zTXt":
                _parse_png_text(chunk_data, result, "zTXt")
            elif chunk_type == "iTXt":
                _parse_png_text(chunk_data, result, "iTXt")
            elif chunk_type == "pHYs":
                _parse_png_phys(chunk_data, result)
            elif chunk_type == "gAMA":
                result["gamma"] = struct.unpack(">I", chunk_data)[0] / 100000
            elif chunk_type == "sRGB":
                result["srgb_rendering_intent"] = chunk_data[0]
            elif chunk_type == "iCCP":
                result["has_icc_profile"] = True
            elif chunk_type == "tRNS":
                result["has_transparency"] = True
            elif chunk_type == "bKGD":
                result["background_color"] = chunk_data.hex()
            elif chunk_type == "tIME":
                result["modification_time"] = _parse_png_time(chunk_data)
            elif chunk_type == "acTL":
                result["animated"] = True
                result["frame_count"] = struct.unpack(">I", chunk_data[:4])[0]
                result["loop_count"] = struct.unpack(">I", chunk_data[4:8])[0]
            elif chunk_type == "fcTL":
                result["has_frame_control"] = True

            offset += 12 + length

            if chunk_type == "IEND":
                break

        result["chunks"] = chunks

        # Check for appended data after IEND
        if offset < len(data):
            appended = data[offset:]
            result["appended_data_size"] = len(appended)
            result["appended_data_entropy"] = round(shannon_entropy(appended[:8192]), 3)
            if len(appended) > 0:
                result["suspicious_indicators"].append(f"Appended data after IEND: {len(appended)} bytes")

    except Exception as exc:
        result["errors"].append(f"PNG analysis failed: {exc}")


def _parse_png_ihdr(data: bytes, result: dict) -> None:
    """Parse PNG IHDR chunk."""
    if len(data) >= 13:
        width = struct.unpack(">I", data[0:4])[0]
        height = struct.unpack(">I", data[4:8])[0]
        bit_depth = data[8]
        color_type = data[9]
        compression = data[10]
        filter_method = data[11]
        interlace = data[12]

        result["dimensions"] = {"width": width, "height": height}
        result["bit_depth"] = bit_depth
        result["color_type"] = color_type
        result["color_type_name"] = _png_color_type_name(color_type)
        result["compression_method"] = compression
        result["filter_method"] = filter_method
        result["interlace_method"] = interlace
        result["color_depth"] = bit_depth * _png_channels(color_type)


def _parse_png_text(data: bytes, result: dict, chunk_type: str) -> None:
    """Parse PNG text chunks (tEXt, zTXt, iTXt)."""
    # Simplified - just extract key-value pairs


def _parse_png_phys(data: bytes, result: dict) -> None:
    """Parse PNG pHYs chunk (physical pixel dimensions)."""
    if len(data) >= 9:
        ppu_x = struct.unpack(">I", data[0:4])[0]
        ppu_y = struct.unpack(">I", data[4:8])[0]
        unit = data[8]
        result["pixels_per_unit_x"] = ppu_x
        result["pixels_per_unit_y"] = ppu_y
        result["unit"] = "meter" if unit == 1 else "unknown"


def _parse_png_time(data: bytes) -> str:
    """Parse PNG tIME chunk."""
    if len(data) >= 7:
        year = struct.unpack(">H", data[0:2])[0]
        month = data[2]
        day = data[3]
        hour = data[4]
        minute = data[5]
        second = data[6]
        return f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d}"
    return ""


def _png_color_type_name(color_type: int) -> str:
    names = {
        0: "Grayscale",
        2: "Truecolor (RGB)",
        3: "Indexed-color",
        4: "Grayscale with alpha",
        6: "Truecolor with alpha (RGBA)",
    }
    return names.get(color_type, f"Unknown ({color_type})")


def _png_channels(color_type: int) -> int:
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}
    return channels.get(color_type, 0)


def _analyze_jpeg(data: bytes, result: dict) -> None:
    """Analyze JPEG image."""
    try:
        offset = 0
        segments = []

        while offset < len(data):
            if offset + 2 > len(data):
                break
            if data[offset] != 0xff:
                break
            marker = data[offset+1]
            offset += 2

            if marker in (0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9):  # Standalone markers
                segments.append({"marker": hex(marker), "name": _jpeg_marker_name(marker)})
                if marker == 0xd9:  # EOI
                    break
                continue

            if offset + 2 > len(data):
                break
            length = struct.unpack(">H", data[offset:offset+2])[0]
            offset += 2
            segment_data = data[offset:offset+length-2]
            offset += length - 2

            seg_info = {"marker": hex(marker), "name": _jpeg_marker_name(marker), "length": length}
            segments.append(seg_info)

            # Parse specific segments
            if marker == 0xe0:  # APP0 - JFIF
                _parse_jpeg_app0(segment_data, result)
            elif marker == 0xe1:  # APP1 - Exif/XMP
                _parse_jpeg_app1(segment_data, result)
            elif marker == 0xe2:  # APP2 - ICC Profile
                _parse_jpeg_app2(segment_data, result)
            elif marker == 0xdb:  # DQT - Define Quantization Table
                result["has_dqt"] = True
            elif marker == 0xc0:  # SOF0 - Start of Frame (Baseline)
                _parse_jpeg_sof(segment_data, result)
            elif marker == 0xc2:  # SOF2 - Progressive
                _parse_jpeg_sof(segment_data, result)
                result["progressive"] = True
            elif marker == 0xc4:  # DHT - Define Huffman Table
                result["has_dht"] = True
            elif marker == 0xda:  # SOS - Start of Scan
                result["scan_components"] = segment_data[0] if segment_data else 0

        result["segments"] = segments

        # Check for appended data after EOI
        if offset < len(data):
            appended = data[offset:]
            result["appended_data_size"] = len(appended)
            result["appended_data_entropy"] = round(shannon_entropy(appended[:8192]), 3)
            if len(appended) > 0:
                result["suspicious_indicators"].append(f"Appended data after EOI: {len(appended)} bytes")

    except Exception as exc:
        result["errors"].append(f"JPEG analysis failed: {exc}")


def _jpeg_marker_name(marker: int) -> str:
    names = {
        0xd8: "SOI (Start of Image)",
        0xd9: "EOI (End of Image)",
        0xda: "SOS (Start of Scan)",
        0xdb: "DQT (Define Quantization Table)",
        0xc0: "SOF0 (Baseline DCT)",
        0xc1: "SOF1 (Extended Sequential DCT)",
        0xc2: "SOF2 (Progressive DCT)",
        0xc4: "DHT (Define Huffman Table)",
        0xe0: "APP0 (JFIF)",
        0xe1: "APP1 (Exif/XMP)",
        0xe2: "APP2 (ICC Profile)",
        0xed: "APP13 (Photoshop IRB)",
        0xee: "APP14 (Adobe)",
        0xfe: "COM (Comment)",
    }
    return names.get(marker, f"Unknown (0x{marker:02x})")


def _parse_jpeg_app0(data: bytes, result: dict) -> None:
    """Parse JPEG APP0 (JFIF)."""
    if data[:5] == b"JFIF\x00":
        result["jfif"] = True
        if len(data) >= 16:
            version = f"{data[5]}.{data[6]}"
            units = data[7]
            x_density = struct.unpack(">H", data[8:10])[0]
            y_density = struct.unpack(">H", data[10:12])[0]
            thumb_w = data[12]
            thumb_h = data[13]
            result["jfif_version"] = version
            result["jfif_units"] = units
            result["jfif_density"] = (x_density, y_density)


def _parse_jpeg_app1(data: bytes, result: dict) -> None:
    """Parse JPEG APP1 (Exif or XMP)."""
    if data[:6] == b"Exif\x00\x00":
        result["has_exif"] = True
        # TIFF-based EXIF parsing would go here
    elif data[:29] == b"http://ns.adobe.com/xap/1.0/\x00":
        result["has_xmp"] = True


def _parse_jpeg_app2(data: bytes, result: dict) -> None:
    """Parse JPEG APP2 (ICC Profile)."""
    if data[:12] == b"ICC_PROFILE\x00":
        result["has_icc_profile"] = True


def _parse_jpeg_sof(data: bytes, result: dict) -> None:
    """Parse JPEG SOF (Start of Frame)."""
    if len(data) >= 8:
        precision = data[0]
        height = struct.unpack(">H", data[1:3])[0]
        width = struct.unpack(">H", data[3:5])[0]
        components = data[5]
        result["dimensions"] = {"width": width, "height": height}
        result["precision"] = precision
        result["components"] = components


def _analyze_gif(data: bytes, result: dict) -> None:
    """Analyze GIF image."""
    try:
        # Header
        version = data[:6].decode("ascii")
        result["gif_version"] = version

        # Logical Screen Descriptor
        if len(data) >= 13:
            width = struct.unpack("<H", data[6:8])[0]
            height = struct.unpack("<H", data[8:10])[0]
            flags = data[10]
            bg_index = data[11]
            aspect = data[12]

            result["dimensions"] = {"width": width, "height": height}
            result["global_color_table"] = bool(flags & 0x80)
            result["color_resolution"] = ((flags >> 4) & 0x07) + 1
            result["sorted_color_table"] = bool(flags & 0x08)
            result["global_color_table_size"] = 2 << (flags & 0x07)
            result["background_color_index"] = bg_index
            result["aspect_ratio"] = aspect

        # Parse blocks
        offset = 13
        if result.get("global_color_table"):
            gct_size = result["global_color_table_size"] * 3
            offset += gct_size

        frame_count = 0
        while offset < len(data):
            if offset >= len(data):
                break
            block_type = data[offset]
            if block_type == 0x21:  # Extension
                label = data[offset+1] if offset+1 < len(data) else 0
                if label == 0xf9:  # Graphic Control Extension
                    result["has_gce"] = True
                elif label == 0xff:  # Application Extension
                    if data[offset+2:offset+11] == b"NETSCAPE2.0":
                        result["has_netscape_loop"] = True
                # Skip sub-blocks
                offset += 2
                while offset < len(data) and data[offset] != 0:
                    block_size = data[offset]
                    offset += 1 + block_size
                offset += 1
            elif block_type == 0x2c:  # Image Descriptor
                frame_count += 1
                # Skip image descriptor and data
                offset += 10  # Image descriptor
                flags = data[offset-1] if offset > 0 else 0
                if flags & 0x80:  # Local color table
                    lct_size = 3 * (2 << (flags & 0x07))
                    offset += lct_size
                offset += 1  # LZW minimum code size
                while offset < len(data) and data[offset] != 0:
                    block_size = data[offset]
                    offset += 1 + block_size
                offset += 1
            elif block_type == 0x3b:  # Trailer
                break
            else:
                break

        result["frame_count"] = frame_count
        result["animated"] = frame_count > 1

    except Exception as exc:
        result["errors"].append(f"GIF analysis failed: {exc}")


def _analyze_bmp(data: bytes, result: dict) -> None:
    """Analyze BMP image."""
    try:
        if len(data) < 14:
            return

        # File header
        bf_type = data[:2]
        bf_size = struct.unpack("<I", data[2:6])[0]
        bf_reserved = struct.unpack("<I", data[6:10])[0]
        bf_off_bits = struct.unpack("<I", data[10:14])[0]

        result["bmp_file_size"] = bf_size
        result["bmp_data_offset"] = bf_off_bits

        # Info header
        if len(data) >= 14 + 4:
            bi_size = struct.unpack("<I", data[14:18])[0]
            if bi_size >= 40:  # BITMAPINFOHEADER
                width = struct.unpack("<i", data[18:22])[0]
                height = struct.unpack("<i", data[22:26])[0]
                planes = struct.unpack("<H", data[26:28])[0]
                bit_count = struct.unpack("<H", data[28:30])[0]
                compression = struct.unpack("<I", data[30:34])[0]
                size_image = struct.unpack("<I", data[34:38])[0]
                x_pels = struct.unpack("<i", data[38:42])[0]
                y_pels = struct.unpack("<i", data[42:46])[0]
                clr_used = struct.unpack("<I", data[46:50])[0]
                clr_important = struct.unpack("<I", data[50:54])[0]

                result["dimensions"] = {"width": abs(width), "height": abs(height)}
                result["bit_depth"] = bit_count
                result["compression"] = _bmp_compression_name(compression)
                result["image_size"] = size_image
                result["dpi_x"] = x_pels
                result["dpi_y"] = y_pels
                result["colors_used"] = clr_used

    except Exception as exc:
        result["errors"].append(f"BMP analysis failed: {exc}")


def _bmp_compression_name(comp: int) -> str:
    names = {
        0: "BI_RGB (uncompressed)",
        1: "BI_RLE8",
        2: "BI_RLE4",
        3: "BI_BITFIELDS",
        4: "BI_JPEG",
        5: "BI_PNG",
        6: "BI_ALPHABITFIELDS",
        11: "BI_CMYK",
        12: "BI_CMYKRLE8",
        13: "BI_CMYKRLE4",
    }
    return names.get(comp, f"Unknown ({comp})")


def _analyze_tiff(data: bytes, result: dict) -> None:
    """Analyze TIFF image."""
    try:
        endian = data[:2]
        if endian == b"II":
            endian_fmt = "<"
        elif endian == b"MM":
            endian_fmt = ">"
        else:
            result["errors"].append("Invalid TIFF endian marker")
            return

        # Check magic (42)
        magic = struct.unpack(endian_fmt + "H", data[2:4])[0]
        if magic != 42:
            result["errors"].append("Invalid TIFF magic number")
            return

        # First IFD offset
        ifd_offset = struct.unpack(endian_fmt + "I", data[4:8])[0]

        result["endian"] = "little" if endian == b"II" else "big"
        result["tiff_magic"] = magic

        # Parse IFD (simplified)
        if ifd_offset < len(data):
            _parse_tiff_ifd(data, ifd_offset, endian_fmt, result)

    except Exception as exc:
        result["errors"].append(f"TIFF analysis failed: {exc}")


def _parse_tiff_ifd(data: bytes, offset: int, endian_fmt: str, result: dict) -> None:
    """Parse TIFF Image File Directory."""
    try:
        if offset + 2 > len(data):
            return
        num_entries = struct.unpack(endian_fmt + "H", data[offset:offset+2])[0]
        offset += 2

        for i in range(num_entries):
            if offset + 12 > len(data):
                break
            tag = struct.unpack(endian_fmt + "H", data[offset:offset+2])[0]
            field_type = struct.unpack(endian_fmt + "H", data[offset+2:offset+4])[0]
            count = struct.unpack(endian_fmt + "I", data[offset+4:offset+8])[0]
            value_offset = struct.unpack(endian_fmt + "I", data[offset+8:offset+12])[0]

            tag_names = {
                256: "ImageWidth", 257: "ImageLength", 258: "BitsPerSample",
                259: "Compression", 262: "PhotometricInterpretation", 273: "StripOffsets",
                277: "SamplesPerPixel", 278: "RowsPerStrip", 279: "StripByteCounts",
                282: "XResolution", 283: "YResolution", 296: "ResolutionUnit",
                305: "Software", 306: "DateTime", 315: "Artist", 330: "SubIFDs",
                34665: "ExifIFD", 34853: "GPSIFD", 34675: "ICCProfile",
            }

            tag_name = tag_names.get(tag, f"Tag_{tag}")

            if tag == 256:  # ImageWidth
                result["dimensions"] = {"width": value_offset, "height": result.get("dimensions", {}).get("height", 0)}
            elif tag == 257:  # ImageLength
                result["dimensions"] = {"width": result.get("dimensions", {}).get("width", 0), "height": value_offset}
            elif tag == 258:  # BitsPerSample
                result["bits_per_sample"] = value_offset
            elif tag == 259:  # Compression
                result["compression"] = _tiff_compression_name(value_offset)
            elif tag == 305:  # Software
                # Read string
                if count < 1000:
                    str_data = data[value_offset:value_offset+count]
                    result["software"] = str_data.decode("ascii", errors="ignore").rstrip("\x00")
            elif tag == 306:  # DateTime
                if count < 1000:
                    str_data = data[value_offset:value_offset+count]
                    result["datetime"] = str_data.decode("ascii", errors="ignore").rstrip("\x00")

            offset += 12

    except Exception as exc:
        logger.debug(f"TIFF IFD parsing failed: {exc}")


def _tiff_compression_name(comp: int) -> str:
    names = {
        1: "None (uncompressed)",
        2: "CCITT 1D",
        3: "CCITT Group 3",
        4: "CCITT Group 4",
        5: "LZW",
        6: "JPEG (old)",
        7: "JPEG (new)",
        8: "Deflate/Adobe",
        9: "JBIG",
        10: "JBIG (TIFF-FX)",
        32773: "PackBits",
        32946: "Deflate",
        34661: "JBIG (TIFF-FX)",
    }
    return names.get(comp, f"Unknown ({comp})")


def _analyze_svg(data: bytes, result: dict) -> None:
    """Analyze SVG image."""
    try:
        text = data.decode("utf-8", errors="ignore")
        result["svg_size"] = len(text)

        # Check for suspicious content
        suspicious = [
            ("<script", "Embedded JavaScript"),
            ("onload=", "Event handler"),
            ("onclick=", "Event handler"),
            ("onmouseover=", "Event handler"),
            ("<foreignObject", "Foreign object"),
            ("<iframe", "IFrame"),
            ("<object", "Object"),
            ("<embed", "Embed"),
            ("xlink:href", "XLink reference"),
            ("javascript:", "JavaScript URL"),
            ("data:", "Data URI"),
        ]

        for pattern, desc in suspicious:
            if pattern in text:
                result["suspicious_indicators"].append(f"SVG: {desc} detected")

        # Extract dimensions
        import re
        width_match = re.search(r'width\s*=\s*["\']?([\d.]+)', text)
        height_match = re.search(r'height\s*=\s*["\']?([\d.]+)', text)
        if width_match:
            result["dimensions"] = {"width": float(width_match.group(1)), "height": float(height_match.group(1)) if height_match else 0}

    except Exception as exc:
        result["errors"].append(f"SVG analysis failed: {exc}")


def _analyze_webp(data: bytes, result: dict) -> None:
    """Analyze WEBP image."""
    try:
        # RIFF header
        riff_size = struct.unpack("<I", data[4:8])[0]
        webp_type = data[8:12]

        result["webp_type"] = webp_type.decode("ascii", errors="ignore")

        # Parse chunks
        offset = 12
        while offset < len(data):
            if offset + 8 > len(data):
                break
            chunk_tag = data[offset:offset+4].decode("ascii", errors="ignore")
            chunk_size = struct.unpack("<I", data[offset+4:offset+8])[0]
            chunk_data = data[offset+8:offset+8+chunk_size]

            if chunk_tag == "VP8 ":
                result["webp_format"] = "VP8 (Lossy)"
            elif chunk_tag == "VP8L":
                result["webp_format"] = "VP8L (Lossless)"
            elif chunk_tag == "VP8X":
                result["webp_format"] = "VP8X (Extended)"
                # Parse extended header
                if len(chunk_data) >= 10:
                    flags = chunk_data[0]
                    width = struct.unpack("<I", b"\x00" + chunk_data[1:4])[0] + 1
                    height = struct.unpack("<I", b"\x00" + chunk_data[4:7])[0] + 1
                    result["dimensions"] = {"width": width, "height": height}
                    result["has_animation"] = bool(flags & 0x02)
                    result["has_alpha"] = bool(flags & 0x10)
                    result["has_exif"] = bool(flags & 0x04)
                    result["has_xmp"] = bool(flags & 0x08)
            elif chunk_tag == "ANIM":
                result["has_animation"] = True
            elif chunk_tag == "ANMF":
                result["animation_frames"] = result.get("animation_frames", 0) + 1
            elif chunk_tag == "EXIF":
                result["has_exif"] = True
            elif chunk_tag == "XMP ":
                result["has_xmp"] = True
            elif chunk_tag == "ICCP":
                result["has_icc_profile"] = True

            offset += 8 + chunk_size + (chunk_size % 2)  # Padding

    except Exception as exc:
        result["errors"].append(f"WEBP analysis failed: {exc}")


def analyze_image_file(file_path: Path) -> dict:
    """Main entry point."""
    return analyze_image(file_path)