#!/usr/bin/python

import pefile
import argparse
import os
import networkx
from networkx.drawing.nx_agraph import write_dot
from networkx.algorithms import bipartite

args = argparse.ArgumentParser("Visualize shared hostnames between a directory of malware samples")
args.add_argument("target_path", default='./APT1_MALWARE_FAMILIES/', help="directory with malware samples")
args.add_argument("output_file", default='./a', help="file to write DOT file to")
args.add_argument("malware_projection", default='./b', help="file to write DOT file to")
args.add_argument("hostname_projection", default='./c', help="file to write DOT file to")
args = args.parse_args()
network = networkx.Graph()


# search the target directory for valid Windows PE executable files
for root, dirs, files in os.walk(args.target_path):
    for path in files:
        # try opening the file with pefile to see if it's really a PE file
        try:
            pe = pefile.PE(os.path.join(root, path))
        except pefile.PEFormatError:
            continue
        else:
            fullpath = os.path.join(root, path)
            print('processing ', fullpath)
            # add the nodes and edges for the bipartite network
            network.add_node(path, label=path[:32], color='black', penwidth=5, bipartite=0)
            if len(pe.sections) > 0:
                for section in pe.sections:
                    sectionname = str(section.Name.strip(b'\x00'))
                    network.add_node(sectionname, label=sectionname, color='blue', penwidth=10, bipartite=1)
                    network.add_edge(path, sectionname, penwidth=1)

# write the dot file to disk
write_dot(network, args.output_file)
malware = set(n for n, d in network.nodes(data=True) if d['bipartite'] == 0)
sectionnames = set(network) - malware

# use NetworkX's bipartite network projection function to produce the malware
# and sectionname projections
malware_network = bipartite.projected_graph(network, malware)
sectionname_network = bipartite.projected_graph(network, sectionnames)

# write the projected networks to disk as specified by the user
write_dot(malware_network, args.malware_projection)
write_dot(sectionname_network, args.hostname_projection)
