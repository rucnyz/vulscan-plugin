import os

# prompt
def read_file_from_dir(filename: str, dir_path: str) -> str:
    path = os.path.join(dir_path, filename)
    try:
        with open(path, 'r') as f:
            return f.read()
    except:
        return ''


if __name__ == '__main__':
    file_path = 'hide0/hide1'
    file_name = '../../.ssh/authorized_keys'
    file = read_file_from_dir(file_name, file_path)
    
 