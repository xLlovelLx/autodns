import networkx as nx
import matplotlib
import io
matplotlib.use("Agg")  # Use a non-interactive backend for matplotlib
import matplotlib.pyplot as plt

def visualize_dns_graph(data, output_file=None):
    """
    Visualize DNS relationships as a graph.
    
    Args:
        data (dict): DNS data with relationships (e.g., subdomains, records).
        output_file (str): Path to save the graph image (optional).
    """
    graph = nx.DiGraph()

    for record_type, records in data.items():
        if records is None:
            continue
        for record in records:
            # If record is a dict, convert to string or extract key
            if isinstance(record, dict):
                record_str = str(record)
            else:
                record_str = record
            graph.add_edge(record_type, record_str)

    plt.figure(figsize=(10, 8))
    nx.draw(graph, with_labels=True, node_color="lightblue", font_size=10, font_weight="bold")
    if output_file:
        plt.savefig(output_file)
        print(f"Graph saved to {output_file}")
        plt.close()
        return None
    else:
        img = io.BytesIO()
        plt.savefig(img, format='png')
        plt.close()
        img.seek(0)
        return img.getvalue()
    
def generate_graph_image_from_history(history_entry):
    """
    Generate a graph image bytes from a history entry's result data.
    
    Args:
        history_entry (dict): A history entry containing 'result' key with DNS data.
    
    Returns:
        bytes: PNG image bytes of the graph.
    """
    def extract_relevant_data(results):
        extracted = {}
        # Extract subdomains from passive, brute, tld
        for key in ['Passive', 'Brute-Force', 'TLD']:
            if key in results:
                subdomains = []
                val = results[key]
                if isinstance(val, dict):
                    for subkey, subval in val.items():
                        if isinstance(subval, list):
                            for item in subval:
                                if isinstance(item, dict):
                                    # For TLD, extract 'domain' key if present
                                    if key == 'TLD' and 'domain' in item:
                                        subdomains.append(item['domain'])
                                    else:
                                        subdomains.append(str(item))
                                else:
                                    subdomains.append(item)
                        else:
                            if isinstance(subval, dict):
                                if key == 'TLD' and 'domain' in subval:
                                    subdomains.append(subval['domain'])
                                else:
                                    subdomains.append(str(subval))
                            else:
                                subdomains.append(subval)
                elif isinstance(val, list):
                    for item in val:
                        if isinstance(item, dict):
                            if key == 'TLD' and 'domain' in item:
                                subdomains.append(item['domain'])
                            else:
                                subdomains.append(str(item))
                        else:
                            subdomains.append(item)
                extracted[key] = list(set(subdomains))
        # Extract NS records from DoH, DoT, Active
        for key in ['DoH', 'DoT', 'Active']:
            if key in results:
                ns_records = []
                val = results[key]
                if isinstance(val, dict):
                    for subkey, subval in val.items():
                        if subkey == 'NS':
                            if isinstance(subval, list):
                                for item in subval:
                                    if isinstance(item, dict):
                                        ns_records.append(str(item))
                                    else:
                                        ns_records.append(item)
                            else:
                                if isinstance(subval, dict):
                                    ns_records.append(str(subval))
                                else:
                                    ns_records.append(subval)
                extracted[key] = list(set(ns_records))
        return extracted

    data = history_entry.get('result', {})
    filtered_data = extract_relevant_data(data)
    return visualize_dns_graph(filtered_data)
