lines = open('flagchecker.sym').read().strip().split('\n')
out_lines = []
for line in lines:
    if "flag" in line:
        out_lines.append(line)
with open('flagchecker.sym', 'w') as f:
    f.write('\n'.join(out_lines))