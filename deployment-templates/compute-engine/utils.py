def glob_expr_matching_patches(forseti_version):
    segments = forseti_version[6:].split('.')
    if forseti_version[:6] == "tags/v" and all(segment.isdigit() for segment in segments):
        return "v{}.{}.{{[0-9],[0-9][0-9]}}".format(segments[0], segments[1])
    else:
        return None
