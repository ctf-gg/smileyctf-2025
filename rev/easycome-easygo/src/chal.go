package main

import (
	"fmt"
)

func main() {
	inCh2 := make(chan int)
	inCh3 := make(chan byte)
	outCh2 := make(chan byte)
	outCh3 := make(chan byte)
	resultCh := make(chan bool)

	var input []byte
	fmt.Print("> ")
	// Read input from stdin
	_, err := fmt.Scanf("%s", &input)
	if err != nil {
		fmt.Println("err: ", err)
		return
	}

	if len(input) != 24 {
		fmt.Println("Incorrect!")
		return
	}

	// Base
	go func() {
		array2 := []byte{62, 132, 81, 242, 193, 15, 48, 71, 111, 45, 93, 68, 76, 177, 26, 108, 81, 18, 66, 172, 130, 204, 87, 2}
		for {
			index, ok := <-inCh2
			if !ok {
				return
			}
			if index < len(array2) {
				outCh2 <- array2[index]
			} else {
				outCh2 <- 0
			}
		}
	}()

	// Key 2
	go func() {
		array3 := []byte{190, 214, 155, 196, 166, 239, 18, 9, 70, 77, 68, 131, 5, 59, 22, 106, 149, 163, 62, 100, 244, 31, 230, 36}
		i := 0
		for {
			val, ok := <-inCh3
			if !ok {
				return
			}
			outCh3 <- val ^ array3[i]
			i++
		}
	}()

	// Process
	go func() {
		idxs := []int{21, 23, 1, 3, 14, 18, 13, 0, 20, 10, 6, 11, 17, 2, 15, 8, 9, 12, 16, 4, 22, 7, 5, 19}
		enc := []byte{92, 239, 51, 13, 146, 214, 196, 88, 172, 35, 25, 246, 118, 4, 37, 119, 208, 219, 31, 144, 147, 60, 144, 245}
		for i, val := range input {
			// Send index to both readers
			inCh2 <- idxs[i]
			val2 := <-outCh2

			inCh3 <- val ^ val2
			val3 := <-outCh3

			if val3 != enc[i] {
				resultCh <- false
				return
			}
		}

		resultCh <- true
	}()

	correct := <-resultCh
	if correct {
		fmt.Println("Correct!")
	} else {
		fmt.Println("Incorrect!")
	}
}
