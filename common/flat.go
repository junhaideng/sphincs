package common

func Flatten(data [][]byte) []byte {
	if len(data) == 0 {
		return []byte{}
	}
	res := make([]byte, 0, len(data)*len(data[0]))
	for i := 0; i < len(data); i++ {
		res = append(res, data[i]...)
	}
	return res
}

// Ravel 将一个一维数组转换成二维数组
// n 表示每一个数组中包含的数量，二维数组的长度为 len(data) / n
func Ravel(data []byte, n int) [][]byte {
	if len(data)*8%n != 0 {
		return nil
	}
	length := len(data) / n
	res := make([][]byte, length)
	for i := 0; i < length; i++ {
		res[i] = data[i*n : (i+1)*n]
	}
	return res
}
