"""
MALINFO — Office Document Static Analysis (OLE, OOXML, RTF, PDF).

Analysis for Microsoft Office documents, RTF, and PDF files.
Includes: VBA macro extraction, XLM/Excel 4.0 macro detection, OLE object parsing,
external relationships, embedded payloads, JavaScript detection.
"""
from __future__ import annotations

import logging
import zipfile
from pathlib import Path

from app.analysis.strings_entropy import shannon_entropy

logger = logging.getLogger("malinfo.ole_analysis")

def analyze_ole_document(file_path: Path) -> dict:
    """
    Comprehensive Office document analysis (OLE/CFB and OOXML formats).
    """
    result: dict = {
        "available": True,
        "format": "unknown",
        "format_details": "",
        "vba_macros": [],
        "xlm_macros": [],
        "ole_objects": [],
        "external_relationships": [],
        "embedded_files": [],
        "javascript": [],
        "suspicious_indicators": [],
        "metadata": {},
        "entropy": 0.0,
    }

    try:
        # Determine format by magic bytes
        with open(file_path, "rb") as f:
            header = f.read(8)
        
        if header[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            # OLE/CFB (legacy .doc, .xls, .ppt)
            result["format"] = "OLE/CFB"
            return _analyze_ole_cfb(file_path, result)
        elif header[:4] == b"PK\x03\x04":
            # ZIP-based (OOXML: .docx, .xlsx, .pptx)
            result["format"] = "OOXML"
            return _analyze_ooxml(file_path, result)
        elif header[:5] == b"%PDF":
            # PDF
            result["format"] = "PDF"
            return _analyze_pdf(file_path, result)
        elif header[:5] == b"{\\rtf":
            # RTF
            result["format"] = "RTF"
            return _analyze_rtf(file_path, result)
        else:
            result["format_details"] = f"Unknown format (magic: {header.hex()})"
            return result
            
    except Exception as exc:
        logger.exception("Office document analysis failed")
        return {"error": f"Failed to analyze document: {exc}", "available": False}


def _analyze_ole_cfb(file_path: Path, result: dict) -> dict:
    """Analyze OLE Compound File Binary format."""
    try:
        import olefile
    except ImportError:
        result["error"] = "olefile library not installed"
        return result

    try:
        ole = olefile.OleFileIO(str(file_path))
        result["format_details"] = "OLE Compound File Binary"
        
        # List all streams
        streams = ole.listdir()
        result["streams"] = ["/".join(s) for s in streams]
        
        # Check for VBA macros
        if ole.exists("Macros") or any("VBA" in "/".join(s) for s in streams):
            result["has_vba"] = True
            vba_info = _extract_vba_macros(ole)
            result["vba_macros"] = vba_info
        
        # Check for XLM macros (Excel 4.0)
        if any("XLMacros" in "/".join(s) or "xl/" in "/".join(s).lower() for s in streams):
            result["has_xlm"] = True
            xlm_info = _extract_xlm_macros(ole)
            result["xlm_macros"] = xlm_info
        
        # Check for embedded OLE objects
        ole_objects = _extract_ole_objects(ole)
        result["ole_objects"] = ole_objects
        
        # Metadata
        if ole.exists("SummaryInformation"):
            result["metadata"]["summary"] = _get_summary_info(ole)
        if ole.exists("DocumentSummaryInformation"):
            result["metadata"]["document_summary"] = _get_document_summary_info(ole)
        
        ole.close()
        
    except Exception as exc:
        logger.debug(f"OLE CFB analysis failed: {exc}")
        result["error"] = str(exc)
    
    return result


def _extract_vba_macros(ole) -> list[dict]:
    """Extract VBA macro information."""
    macros = []
    try:
        # Use olevba if available for detailed parsing
        try:
            import olevba
            # olevba can parse VBA from OLE
            vba_parser = olevba.VBA_Parser(ole)
            if vba_parser.detect_vba_macros():
                for kw_type, keyword, description in vba_parser.extract_macros():
                    macros.append({
                        "type": kw_type,
                        "keyword": keyword,
                        "description": description,
                    })
            vba_parser.close()
        except ImportError:
            # Fallback: just note VBA presence
            macros.append({"note": "VBA macros detected (olevba not installed for detailed extraction)"})
    except Exception as exc:
        logger.debug(f"VBA extraction failed: {exc}")
        macros.append({"error": str(exc)})
    return macros


def _extract_xlm_macros(ole) -> list[dict]:
    """Extract Excel 4.0 (XLM) macro information."""
    xlm = []
    try:
        # XLM macros are in sheet streams
        # This is a placeholder - full XLM parsing requires specialized tools
        xlm.append({"note": "XLM macro streams detected (detailed parsing requires xlrd/openpyxl)"})
    except Exception as exc:
        logger.debug(f"XLM extraction failed: {exc}")
        xlm.append({"error": str(exc)})
    return xlm


def _extract_ole_objects(ole) -> list[dict]:
    """Extract embedded OLE objects."""
    objects = []
    try:
        # OLE objects are typically in streams with specific names
        for stream_path in ole.listdir():
            path = "/".join(stream_path)
            # Look for embedded objects
            if any(keyword in path.lower() for keyword in ["object", "ole", "embed", "package"]):
                try:
                    data = ole.openstream(stream_path).read()
                    objects.append({
                        "path": path,
                        "size": len(data),
                        "entropy": round(shannon_entropy(data), 3),
                        "magic": data[:8].hex() if len(data) >= 8 else "",
                    })
                except Exception:
                    pass
    except Exception as exc:
        logger.debug(f"OLE object extraction failed: {exc}")
    return objects


def _get_summary_info(ole) -> dict:
    """Get summary information from OLE."""
    try:
        props = ole.get_metadata()
        return {
            "title": props.title,
            "subject": props.subject,
            "author": props.author,
            "keywords": props.keywords,
            "comments": props.comments,
            "template": props.template,
            "last_saved_by": props.last_saved_by,
            "revision": props.revision,
            "total_edit_time": props.total_edit_time,
            "last_printed": str(props.last_printed) if props.last_printed else None,
            "create_time": str(props.create_time) if props.create_time else None,
            "last_save_time": str(props.last_save_time) if props.last_save_time else None,
            "page_count": props.page_count,
            "word_count": props.word_count,
            "char_count": props.char_count,
            "security": props.security,
        }
    except Exception:
        return {}


def _get_document_summary_info(ole) -> dict:
    """Get document summary information from OLE."""
    try:
        props = ole.get_metadata()
        return {
            "category": props.category,
            "presentation_format": props.presentation_format,
            "manager": props.manager,
            "company": props.company,
            "links_dirty": props.links_dirty,
            "char_count_with_spaces": props.char_count_with_spaces,
        }
    except Exception:
        return {}


def _analyze_ooxml(file_path: Path, result: dict) -> dict:
    """Analyze OOXML format (.docx, .xlsx, .pptx)."""
    try:
        with zipfile.ZipFile(file_path, "r") as z:
            names = z.namelist()
            result["format_details"] = "Office Open XML (ZIP-based)"
            result["files"] = names
            
            # Determine document type
            if "word/document.xml" in names:
                result["document_type"] = "Word (.docx)"
            elif "xl/workbook.xml" in names:
                result["document_type"] = "Excel (.xlsx)"
            elif "ppt/presentation.xml" in names:
                result["document_type"] = "PowerPoint (.pptx)"
            
            # Content Types
            if "[Content_Types].xml" in names:
                result["content_types"] = z.read("[Content_Types].xml").decode("utf-8", errors="ignore")
            
            # Relationships
            rels = _extract_relationships(z, names)
            result["relationships"] = rels
            result["external_relationships"] = [r for r in rels if r.get("target_mode") == "External"]
            
            # VBA Macros (vbaProject.bin)
            vba_projects = [n for n in names if n.endswith("vbaProject.bin")]
            if vba_projects:
                result["has_vba"] = True
                for vp in vba_projects:
                    data = z.read(vp)
                    result["vba_macros"].append({
                        "path": vp,
                        "size": len(data),
                        "note": "VBA project binary (requires olevba for parsing)",
                    })
            
            # Embedded OLE objects in Word
            if result.get("document_type") == "Word (.docx)":
                ole_objects = _extract_ooxml_ole_objects(z, names)
                result["ole_objects"] = ole_objects
            
            # Excel specific: check for XLM macros, external links
            if result.get("document_type") == "Excel (.xlsx)":
                excel_info = _analyze_excel_ooxml(z, names)
                result.update(excel_info)
            
            # Printer settings (CVE-2021-34527 - PrintNightmare)
            printer_settings = [n for n in names if "printerSettings" in n]
            if printer_settings:
                result["suspicious_indicators"].append("Printer settings found (potential CVE-2021-34527 vector)")
            
            # Core metadata
            if "docProps/core.xml" in names:
                result["metadata"]["core"] = _parse_core_metadata(z.read("docProps/core.xml"))
            if "docProps/app.xml" in names:
                result["metadata"]["app"] = _parse_app_metadata(z.read("docProps/app.xml"))
            
            # Custom XML parts (potential data exfiltration)
            custom_xml = [n for n in names if n.startswith("customXml/")]
            if custom_xml:
                result["custom_xml_parts"] = custom_xml
            
    except Exception as exc:
        logger.debug(f"OOXML analysis failed: {exc}")
        result["error"] = str(exc)
    
    return result


def _extract_relationships(z: zipfile.ZipFile, names: list[str]) -> list[dict]:
    """Extract all relationships (.rels files)."""
    rels = []
    rel_files = [n for n in names if n.endswith(".rels")]
    for rel_file in rel_files:
        try:
            data = z.read(rel_file)
            import xml.etree.ElementTree as ET
            root = ET.fromstring(data)
            for rel in root.findall("{http://schemas.openxmlformats.org/package/2006/relationships}Relationship"):
                rels.append({
                    "source_file": rel_file,
                    "id": rel.get("Id"),
                    "type": rel.get("Type"),
                    "target": rel.get("Target"),
                    "target_mode": rel.get("TargetMode", "Internal"),
                })
        except Exception:
            pass
    return rels


def _extract_ooxml_ole_objects(z: zipfile.ZipFile, names: list[str]) -> list[dict]:
    """Extract embedded OLE objects from OOXML Word documents."""
    objects = []
    # Embedded objects are in word/embeddings/ or referenced in relationships
    embeddings = [n for n in names if n.startswith("word/embeddings/")]
    for emb in embeddings:
        try:
            data = z.read(emb)
            objects.append({
                "path": emb,
                "size": len(data),
                "entropy": round(shannon_entropy(data), 3),
                "magic": data[:8].hex() if len(data) >= 8 else "",
            })
        except Exception:
            pass
    return objects


def _analyze_excel_ooxml(z: zipfile.ZipFile, names: list[str]) -> dict:
    """Excel-specific OOXML analysis."""
    result = {}
    
    # External links
    ext_links = [n for n in names if n.startswith("xl/externalLinks/")]
    if ext_links:
        result["external_links"] = []
        for el in ext_links:
            try:
                data = z.read(el)
                result["external_links"].append({
                    "file": el,
                    "content": data.decode("utf-8", errors="ignore")[:500],
                })
            except Exception:
                pass
    
    # VBA project (already handled)
    # Sheet protection, formulas, etc.
    sheets = [n for n in names if n.startswith("xl/worksheets/sheet") and n.endswith(".xml")]
    result["sheet_count"] = len(sheets)
    
    # Check for Excel 4.0 macros (stored in xl/macrosheet.xml or similar)
    macro_sheets = [n for n in names if "macro" in n.lower()]
    if macro_sheets:
        result["has_xlm_macros"] = True
        result["macro_sheets"] = macro_sheets
    
    return result


def _parse_core_metadata(data: bytes) -> dict:
    """Parse docProps/core.xml."""
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(data)
        ns = {
            "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
            "dc": "http://purl.org/dc/elements/1.1/",
            "dcterms": "http://purl.org/dc/terms/",
            "xsi": "http://www.w3.org/2001/XMLSchema-instance",
        }
        return {
            "title": _xml_text(root, "dc:title", ns),
            "subject": _xml_text(root, "dc:subject", ns),
            "creator": _xml_text(root, "dc:creator", ns),
            "keywords": _xml_text(root, "cp:keywords", ns),
            "description": _xml_text(root, "dc:description", ns),
            "last_modified_by": _xml_text(root, "cp:lastModifiedBy", ns),
            "revision": _xml_text(root, "cp:revision", ns),
            "created": _xml_text(root, "dcterms:created", ns),
            "modified": _xml_text(root, "dcterms:modified", ns),
            "category": _xml_text(root, "cp:category", ns),
        }
    except Exception:
        return {}


def _parse_app_metadata(data: bytes) -> dict:
    """Parse docProps/app.xml."""
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(data)
        ns = {"ep": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"}
        return {
            "application": _xml_text(root, "ep:Application", ns),
            "app_version": _xml_text(root, "ep:AppVersion", ns),
            "company": _xml_text(root, "ep:Company", ns),
            "manager": _xml_text(root, "ep:Manager", ns),
            "total_time": _xml_text(root, "ep:TotalTime", ns),
            "pages": _xml_text(root, "ep:Pages", ns),
            "words": _xml_text(root, "ep:Words", ns),
            "characters": _xml_text(root, "ep:Characters", ns),
            "lines": _xml_text(root, "ep:Lines", ns),
            "paragraphs": _xml_text(root, "ep:Paragraphs", ns),
            "slides": _xml_text(root, "ep:Slides", ns),
            "notes": _xml_text(root, "ep:Notes", ns),
            "hidden_slides": _xml_text(root, "ep:HiddenSlides", ns),
        }
    except Exception:
        return {}


def _xml_text(root, path: str, ns: dict) -> str | None:
    elem = root.find(path, ns)
    return elem.text if elem is not None else None


def _analyze_pdf(file_path: Path, result: dict) -> dict:
    """Analyze PDF document."""
    try:
        import fitz  # PyMuPDF
    except ImportError:
        result["error"] = "PyMuPDF (fitz) not installed for PDF analysis"
        return result

    try:
        doc = fitz.open(str(file_path))
        result["format_details"] = f"PDF {doc.metadata.get('format', '')}"
        result["page_count"] = doc.page_count
        result["metadata"] = doc.metadata
        
        # Check for JavaScript
        js_found = []
        for page_num in range(doc.page_count):
            page = doc[page_num]
            # Check for JS in page
            if page.get_javascript():
                js_found.append({
                    "page": page_num + 1,
                    "javascript": page.get_javascript()[:500],
                })
            
            # Check for actions
            annots = page.annots()
            if annots:
                for annot in annots:
                    if annot.type[1] == "Link":
                        uri = annot.info.get("uri", "")
                        if uri:
                            result["external_relationships"].append({
                                "type": "URI",
                                "target": uri,
                                "page": page_num + 1,
                            })
        
        if js_found:
            result["javascript"] = js_found
            result["suspicious_indicators"].append(f"JavaScript found on {len(js_found)} page(s)")
        
        # Check for embedded files
        embedded_count = doc.embfile_count()
        if embedded_count > 0:
            result["embedded_files_count"] = embedded_count
            result["embedded_files"] = []
            for i in range(embedded_count):
                info = doc.embfile_info(i)
                result["embedded_files"].append({
                    "name": info.get("filename", f"embedded_{i}"),
                    "size": info.get("size", 0),
                    "mime": info.get("mime_type", ""),
                })
        
        # Check for forms
        if doc.is_form_pdf:
            result["has_forms"] = True
            result["suspicious_indicators"].append("PDF contains interactive forms")
        
        # Check for launch actions
        for page_num in range(doc.page_count):
            page = doc[page_num]
            links = page.get_links()
            for link in links:
                if link.get("kind") == fitz.LINK_LAUNCH:
                    result["suspicious_indicators"].append(f"Launch action on page {page_num + 1}: {link.get('file', '')}")
        
        doc.close()
        
    except Exception as exc:
        logger.debug(f"PDF analysis failed: {exc}")
        result["error"] = str(exc)
    
    return result


def _analyze_rtf(file_path: Path, result: dict) -> dict:
    """Analyze RTF document."""
    try:
        data = file_path.read_bytes()
        text = data.decode("utf-8", errors="ignore")
        result["format_details"] = "Rich Text Format"
        result["size"] = len(data)
        
        # Look for OLE objects in RTF
        # RTF OLE objects are in {\object ...} or {\objdata ...}
        import re
        ole_matches = list(re.finditer(r'\\objdata\s+([0-9a-fA-F]+)', text))
        if ole_matches:
            result["ole_objects"] = []
            for m in ole_matches[:10]:  # Limit
                hex_data = m.group(1)
                try:
                    obj_data = bytes.fromhex(hex_data)
                    result["ole_objects"].append({
                        "position": m.start(),
                        "size": len(obj_data),
                        "entropy": round(shannon_entropy(obj_data), 3),
                        "magic": obj_data[:8].hex() if len(obj_data) >= 8 else "",
                    })
                except Exception:
                    pass
        
        # Look for embedded files (\*\objdata or \*\objalias)
        # Check for suspicious RTF constructs
        suspicious_patterns = [
            (r'\\objclass\s+([^\s}]+)', "OLE class"),
            (r'\\objdata', "OLE data"),
            (r'\\field.*\\fldinst\s+([^\s}]+)', "Field instruction"),
            (r'\\pict', "Picture (potential exploit)"),
            (r'\\shppict', "Shape picture"),
        ]
        for pattern, desc in suspicious_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                result["suspicious_indicators"].append(f"RTF contains {desc}")
        
        # Check for hex-encoded payloads
        hex_strings = re.findall(r'[0-9a-fA-F]{100,}', text)
        if hex_strings:
            result["suspicious_indicators"].append(f"Long hex strings found ({len(hex_strings)} instances)")
        
    except Exception as exc:
        logger.debug(f"RTF analysis failed: {exc}")
        result["error"] = str(exc)
    
    return result