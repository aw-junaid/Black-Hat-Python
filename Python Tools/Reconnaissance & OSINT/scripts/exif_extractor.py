#!/usr/bin/env python3
"""
EXIF Metadata Extraction Tool - Images and Documents
For authorized security testing only
"""
import sys
import os
import json
import struct
import hashlib
from datetime import datetime
from collections import defaultdict

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    print("[!] Pillow not installed: pip install Pillow")

class EXIFExtractor:
    def __init__(self):
        self.results = []
        self.stats = defaultdict(int)
        
        # Common file signatures
        self.file_signatures = {
            b'\xff\xd8\xff': 'JPEG',
            b'\x89PNG\r\n\x1a\n': 'PNG',
            b'GIF87a': 'GIF',
            b'GIF89a': 'GIF',
            b'%PDF': 'PDF',
            b'PK\x03\x04': 'DOCX/XLSX/PPTX',
            b'\xd0\xcf\x11\xe0': 'DOC/XLS/PPT'
        }
        
        # Sensitive EXIF tags
        self.sensitive_tags = [
            'Make', 'Model', 'Software', 'Artist', 'Copyright',
            'ImageDescription', 'UserComment', 'GPSInfo',
            'SerialNumber', 'CameraOwnerName', 'BodySerialNumber',
            'LensMake', 'LensModel', 'LensSerialNumber',
            'Creator', 'Author', 'Producer', 'CreatorTool'
        ]
    
    def detect_file_type(self, filepath):
        """Detect file type from magic bytes"""
        try:
            with open(filepath, 'rb') as f:
                header = f.read(8)
            
            for sig, filetype in self.file_signatures.items():
                if header.startswith(sig):
                    return filetype
        except:
            pass
        
        return 'Unknown'
    
    def extract_jpeg_exif(self, filepath):
        """Extract EXIF data from JPEG"""
        if not PIL_AVAILABLE:
            return self._extract_exif_raw(filepath)
        
        try:
            image = Image.open(filepath)
            exif_data = image._getexif()
            
            if not exif_data:
                return {}
            
            metadata = {}
            
            for tag_id, value in exif_data.items():
                tag_name = TAGS.get(tag_id, tag_id)
                
                # Handle GPS data
                if tag_name == 'GPSInfo':
                    gps_data = {}
                    for gps_id, gps_value in value.items():
                        gps_name = GPSTAGS.get(gps_id, gps_id)
                        gps_data[gps_name] = str(gps_value)
                    metadata['GPSInfo'] = gps_data
                    
                    # Convert GPS coordinates
                    if 'GPSLatitude' in gps_data and 'GPSLongitude' in gps_data:
                        lat = self._convert_gps(gps_data['GPSLatitude'])
                        lon = self._convert_gps(gps_data['GPSLongitude'])
                        metadata['GPS_Coordinates'] = f"{lat}, {lon}"
                        metadata['Google_Maps'] = f"https://maps.google.com/?q={lat},{lon}"
                
                # Skip binary data
                elif isinstance(value, bytes):
                    if len(value) < 100:
                        metadata[tag_name] = value.hex()
                else:
                    metadata[tag_name] = str(value)
            
            return metadata
            
        except Exception as e:
            print(f"[-] EXIF extraction error: {e}")
            return {}
    
    def _extract_exif_raw(self, filepath):
        """Extract EXIF without PIL (raw parsing)"""
        metadata = {}
        
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            
            # Look for EXIF header
            if b'Exif\x00\x00' in data:
                exif_start = data.index(b'Exif\x00\x00') + 6
                
                # Parse TIFF header
                if data[exif_start:exif_start+2] == b'\x49\x49':
                    byte_order = 'little'
                elif data[exif_start:exif_start+2] == b'\x4d\x4d':
                    byte_order = 'big'
                else:
                    return metadata
                
                # Basic EXIF parsing
                ifd_offset = struct.unpack(
                    '>I' if byte_order == 'big' else '<I',
                    data[exif_start+4:exif_start+8]
                )[0]
                
                metadata['EXIF'] = f"Found at offset {exif_start}"
            
            # Look for other metadata
            strings = []
            for i in range(0, len(data) - 4):
                try:
                    chunk = data[i:i+4]
                    if all(32 <= b < 127 for b in chunk):
                        strings.append(chunk.decode('ascii'))
                except:
                    continue
            
            if strings:
                metadata['Strings_Found'] = len(strings)
        
        except Exception as e:
            pass
        
        return metadata
    
    def _convert_gps(self, gps_value):
        """Convert GPS coordinates to decimal"""
        try:
            # Parse DMS format
            parts = gps_value.strip('()').split(',')
            degrees = float(parts[0])
            minutes = float(parts[1])
            seconds = float(parts[2])
            
            decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)
            return round(decimal, 6)
        except:
            return gps_value
    
    def extract_png_metadata(self, filepath):
        """Extract PNG metadata"""
        metadata = {}
        
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            
            # PNG chunks
            pos = 8  # Skip PNG signature
            
            while pos < len(data):
                length = struct.unpack('>I', data[pos:pos+4])[0]
                chunk_type = data[pos+4:pos+8].decode('ascii', errors='ignore')
                chunk_data = data[pos+8:pos+8+length]
                
                if chunk_type == 'tEXt':
                    # Text chunk
                    null_pos = chunk_data.find(b'\x00')
                    if null_pos != -1:
                        keyword = chunk_data[:null_pos].decode('utf-8', errors='ignore')
                        text = chunk_data[null_pos+1:].decode('utf-8', errors='ignore')
                        metadata[keyword] = text
                
                elif chunk_type == 'iTXt':
                    # International text
                    null_pos = chunk_data.find(b'\x00')
                    if null_pos != -1:
                        keyword = chunk_data[:null_pos].decode('utf-8', errors='ignore')
                        metadata[keyword] = 'International text present'
                
                elif chunk_type == 'zTXt':
                    # Compressed text
                    null_pos = chunk_data.find(b'\x00')
                    if null_pos != -1:
                        keyword = chunk_data[:null_pos].decode('utf-8', errors='ignore')
                        metadata[keyword] = 'Compressed text present'
                
                pos += 12 + length + 4  # Move to next chunk
            
        except Exception as e:
            print(f"[-] PNG metadata error: {e}")
        
        return metadata
    
    def extract_pdf_metadata(self, filepath):
        """Extract PDF metadata"""
        metadata = {}
        
        try:
            with open(filepath, 'rb') as f:
                content = f.read().decode('latin-1', errors='ignore')
            
            # Look for metadata section
            import re
            
            # Title
            title_match = re.search(r'/Title\s*\(([^)]+)\)', content)
            if title_match:
                metadata['Title'] = title_match.group(1)
            
            # Author
            author_match = re.search(r'/Author\s*\(([^)]+)\)', content)
            if author_match:
                metadata['Author'] = author_match.group(1)
            
            # Subject
            subject_match = re.search(r'/Subject\s*\(([^)]+)\)', content)
            if subject_match:
                metadata['Subject'] = subject_match.group(1)
            
            # Creator
            creator_match = re.search(r'/Creator\s*\(([^)]+)\)', content)
            if creator_match:
                metadata['Creator'] = creator_match.group(1)
            
            # Producer
            producer_match = re.search(r'/Producer\s*\(([^)]+)\)', content)
            if producer_match:
                metadata['Producer'] = producer_match.group(1)
            
            # Creation date
            date_match = re.search(r'/CreationDate\s*\(([^)]+)\)', content)
            if date_match:
                metadata['CreationDate'] = date_match.group(1)
            
            # Mod date
            mod_match = re.search(r'/ModDate\s*\(([^)]+)\)', content)
            if mod_match:
                metadata['ModDate'] = mod_match.group(1)
        
        except Exception as e:
            print(f"[-] PDF metadata error: {e}")
        
        return metadata
    
    def extract_office_metadata(self, filepath):
        """Extract Office document metadata"""
        metadata = {}
        
        try:
            import zipfile
            import xml.etree.ElementTree as ET
            
            with zipfile.ZipFile(filepath, 'r') as zf:
                # Check for core properties
                if 'docProps/core.xml' in zf.namelist():
                    with zf.open('docProps/core.xml') as f:
                        tree = ET.parse(f)
                        root = tree.getroot()
                        
                        ns = {
                            'cp': 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties',
                            'dc': 'http://purl.org/dc/elements/1.1/',
                            'dcterms': 'http://purl.org/dc/terms/'
                        }
                        
                        creator = root.find('.//dc:creator', ns)
                        if creator is not None:
                            metadata['Creator'] = creator.text
                        
                        last_modified = root.find('.//dcterms:modified', ns)
                        if last_modified is not None:
                            metadata['LastModified'] = last_modified.text
                        
                        created = root.find('.//dcterms:created', ns)
                        if created is not None:
                            metadata['Created'] = created.text
                        
                        title = root.find('.//dc:title', ns)
                        if title is not None:
                            metadata['Title'] = title.text
                        
                        subject = root.find('.//dc:subject', ns)
                        if subject is not None:
                            metadata['Subject'] = subject.text
                
                # Check for app properties
                if 'docProps/app.xml' in zf.namelist():
                    with zf.open('docProps/app.xml') as f:
                        tree = ET.parse(f)
                        root = tree.getroot()
                        
                        ns = {
                            '': 'http://schemas.openxmlformats.org/officeDocument/2006/extended-properties'
                        }
                        
                        application = root.find('.//Application', ns)
                        if application is not None:
                            metadata['Application'] = application.text
                        
                        company = root.find('.//Company', ns)
                        if company is not None:
                            metadata['Company'] = company.text
        
        except Exception as e:
            print(f"[-] Office metadata error: {e}")
        
        return metadata
    
    def analyze_file(self, filepath):
        """Analyze a single file for metadata"""
        print(f"[*] Analyzing: {filepath}")
        
        file_type = self.detect_file_type(filepath)
        file_size = os.path.getsize(filepath)
        
        result = {
            'filename': os.path.basename(filepath),
            'filepath': filepath,
            'type': file_type,
            'size': file_size,
            'size_human': self._human_size(file_size),
            'md5': self._hash_file(filepath, 'md5'),
            'sha256': self._hash_file(filepath, 'sha256'),
            'metadata': {}
        }
        
        # Extract metadata based on file type
        if file_type == 'JPEG':
            result['metadata'] = self.extract_jpeg_exif(filepath)
        elif file_type == 'PNG':
            result['metadata'] = self.extract_png_metadata(filepath)
        elif file_type == 'PDF':
            result['metadata'] = self.extract_pdf_metadata(filepath)
        elif file_type == 'DOCX/XLSX/PPTX':
            result['metadata'] = self.extract_office_metadata(filepath)
        
        # Check for sensitive information
        sensitive = []
        for tag, value in result['metadata'].items():
            if any(sensitive_tag.lower() in tag.lower() for sensitive_tag in self.sensitive_tags):
                sensitive.append({tag: value})
        
        if sensitive:
            result['sensitive_info'] = sensitive
            print(f"    [!] Found {len(sensitive)} sensitive metadata items")
        
        # Check for GPS coordinates
        if 'GPS_Coordinates' in result['metadata']:
            print(f"    [+] GPS: {result['metadata']['GPS_Coordinates']}")
            print(f"    [+] Maps: {result['metadata']['Google_Maps']}")
        
        self.results.append(result)
        self.stats[file_type] += 1
        
        return result
    
    def _hash_file(self, filepath, algorithm='md5'):
        """Calculate file hash"""
        try:
            h = hashlib.new(algorithm)
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    h.update(chunk)
            return h.hexdigest()
        except:
            return ''
    
    def _human_size(self, size):
        """Convert bytes to human readable"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} PB"
    
    def scan_directory(self, path, recursive=True):
        """Scan directory for files with metadata"""
        print(f"[*] Scanning directory: {path}")
        
        extensions = ['.jpg', '.jpeg', '.png', '.gif', '.tiff', '.bmp',
                     '.pdf', '.docx', '.xlsx', '.pptx', '.doc', '.xls']
        
        for root, dirs, files in os.walk(path):
            for filename in files:
                if any(filename.lower().endswith(ext) for ext in extensions):
                    filepath = os.path.join(root, filename)
                    self.analyze_file(filepath)
            
            if not recursive:
                break
        
        return self.results
    
    def generate_report(self):
        """Generate metadata report"""
        report = {
            'scan_time': datetime.now().isoformat(),
            'total_files': len(self.results),
            'file_types': dict(self.stats),
            'gps_locations': [],
            'sensitive_findings': [],
            'files': self.results
        }
        
        # Extract GPS locations
        for result in self.results:
            if 'GPS_Coordinates' in result.get('metadata', {}):
                report['gps_locations'].append({
                    'file': result['filename'],
                    'coordinates': result['metadata']['GPS_Coordinates'],
                    'maps_url': result['metadata']['Google_Maps']
                })
            
            if 'sensitive_info' in result:
                report['sensitive_findings'].append({
                    'file': result['filename'],
                    'info': result['sensitive_info']
                })
        
        # Save report
        with open('exif_report.json', 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        # Print summary
        print(f"\n{'='*50}")
        print(f"[*] Metadata Extraction Complete")
        print(f"[+] Files analyzed: {len(self.results)}")
        print(f"[+] File types: {dict(self.stats)}")
        print(f"[+] GPS locations found: {len(report['gps_locations'])}")
        print(f"[+] Sensitive findings: {len(report['sensitive_findings'])}")
        
        if report['gps_locations']:
            print("\n[!] GPS Locations Found:")
            for loc in report['gps_locations']:
                print(f"    {loc['file']}: {loc['coordinates']}")
                print(f"    {loc['maps_url']}")
        
        print(f"\n[+] Report saved to exif_report.json")
        
        return report

def main():
    if len(sys.argv) < 2:
        print("Usage: python exif_extractor.py <file_or_directory>")
        print("Example: python exif_extractor.py photo.jpg")
        print("Example: python exif_extractor.py /path/to/images/")
        sys.exit(1)
    
    target = sys.argv[1]
    
    print("[!] WARNING: Only use for authorized security testing!")
    
    extractor = EXIFExtractor()
    
    if os.path.isfile(target):
        extractor.analyze_file(target)
    elif os.path.isdir(target):
        extractor.scan_directory(target)
    else:
        print(f"[-] Target not found: {target}")
        sys.exit(1)
    
    extractor.generate_report()

if __name__ == "__main__":
    main()
