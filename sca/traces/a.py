import numpy as np

def concatenate_files(file_prefix, file_count, output_file):
    all_data = []
    for i in range(file_count):
        filename = f"{i:02d}th.ct"

        try:
            data = np.fromfile(filename, dtype=np.float64)
            all_data.append(data)
        except FileNotFoundError:
            print(f"파일을 찾을 수 없습니다: {filename}")
        except Exception as e:
            print(f"파일을 읽는 중 오류 발생: {filename}, {e}")
    concatenated_data = np.concatenate(all_data)
    concatenated_data.tofile(output_file)

concatenate_files("00th.ct", 16, "cpa.ct")
