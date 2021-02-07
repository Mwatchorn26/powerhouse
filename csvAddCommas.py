#!/usr/bin/env python
import sys
import csv
import pudb

missing = [3]  # 1-indexed positions of missing values
missing.sort()  # enforce the increasing order
#pudb.set_trace()
filename = sys.argv[1]
print("filename: " + filename)
csvfile= open(filename, newline='') #as csvfile
reader = csv.reader(csvfile, delimiter=',', skipinitialspace=True)
writer = csv.writer(sys.stdout)
header = next(reader)  # get first row (header)
writer.writerow(header)  # write it back
for row in reader:
    if len(row) < len(header):
        # row shorter than header -> insert empty strings
        # inserting changes indices so `missing` must be sorted
        for idx in missing:
            row.insert(idx - 1, '')
    writer.writerow(row)
