import zipfile
import xml.etree.ElementTree as ET
import os

def extract_text(docx_path):
    if not os.path.exists(docx_path):
        return "File not found"
    
    try:
        zip_ref = zipfile.ZipFile(docx_path, 'r')
        doc_xml = zip_ref.read('word/document.xml')
        root = ET.fromstring(doc_xml)
        
        text = ''
        ns = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
        
        for p in root.findall('.//w:p', ns):
            for r in p.findall('.//w:r', ns):
                t = r.find('.//w:t', ns)
                if t is not None:
                    text += str(t.text or "")
            text += '\n'
        return text
    except Exception as e:
        return str(e)

import sys
import io

if __name__ == "__main__":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    print(extract_text('SRS_Honeypot_Updated.docx'))
