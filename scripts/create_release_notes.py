import argparse as ap
import subprocess
import sys

def main():
    parser = ap.ArgumentParser()
    parser.add_argument('--from_tag', required=True, help='From tag')
    parser.add_argument('--to_tag', required=True, help='To tag')
    args = parser.parse_args()

    # get oneliners
    p1 = subprocess.Popen([
        'git',
        'log',
        '%s..%s' % (args.from_tag, args.to_tag),
        '--oneline'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    out, err = p1.communicate()

    if p1.returncode != 0:
        print err
        sys.exit(1)

    commits = []
    for line in out.split('\n'):
        line = '[%s]({}) %s' % (line[0:7], line[7:])
        commits.append(line)

    # get full commit hash
    p2 = subprocess.Popen([
        'git', 'log', '%s..%s' % (args.from_tag, args.to_tag)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    out, err = p2.communicate()

    if p1.returncode != 0:
        print err
        sys.exit(1)

    oneline_ctr = 0
    for line in out.split('\n'):
        if line.startswith('commit'):
            full_hash = line.split(' ')[1].strip()
            commit_href = ('http://github.com/GoogleCloudPlatform'
                           '/forseti-security/commit/%s' % full_hash)
            commits[oneline_ctr] = commits[oneline_ctr].format(commit_href)
            oneline_ctr += 1


    with open('release_%s' % args.to_tag, 'w') as release_notes:
        for commit in commits:
            commit = '%s  \n' % commit
            release_notes.write(commit)

if __name__ == '__main__':
    main()
