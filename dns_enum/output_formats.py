import json
import csv
import xml.etree.ElementTree as ET

def save_as_json(data, output_file):
    """
    Save results as a JSON file.
    """
    with open(output_file, 'w') as json_file:
        json.dump(data, json_file, indent=4)
    print(f"Results saved as JSON: {output_file}")

def save_as_csv(data, output_file):
    """
    Save results as a CSV file.
    """
    with open(output_file, 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        # Write header
        writer.writerow(['Type', 'Name', 'Value'])
        # Write data rows
        for record_type, records in data.items():
            for record in records:
                writer.writerow([record_type, record.get('name', ''), record.get('value', '')])
    print(f"Results saved as CSV: {output_file}")

def save_as_xml(data, output_file):
    """
    Save results as an XML file.
    """
    root = ET.Element('DNSRecords')
    for record_type, records in data.items():
        type_element = ET.SubElement(root, record_type)
        for record in records:
            record_element = ET.SubElement(type_element, 'Record')
            for key, value in record.items():
                sub_element = ET.SubElement(record_element, key)
                sub_element.text = str(value)
    tree = ET.ElementTree(root)
    tree.write(output_file, encoding='utf-8', xml_declaration=True)
    print(f"Results saved as XML: {output_file}")