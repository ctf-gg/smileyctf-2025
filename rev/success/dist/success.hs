import System.Environment (getArgs)
import System.Exit (exitFailure, exitSuccess)
import Data.Bits

checkFlag :: String -> IO ()
checkFlag flag = do
    if length flag /= 39
        then do
            putStrLn "bruh its 39 characters long"
            exitFailure
        else do
            let chars :: [Integer]
                chars = map fromIntegral . map fromEnum $ flag
            if (*) (chars !! 37) (chars !! 15) == 3366 then do
                if (+) (chars !! 8) (chars !! 21) == 197 then do
                    if (*) (chars !! 8) (chars !! 13) == 9215 then do
                        if (*) (chars !! 0) (chars !! 3) == 2714 then do
                            if (+) (chars !! 3) (chars !! 21) == 159 then do
                                if (*) (chars !! 1) (chars !! 20) == 5723 then do
                                    if (.|.) (chars !! 6) (chars !! 37) == 105 then do
                                        if (*) (chars !! 11) (chars !! 7) == 11990 then do
                                            if (.&.) (chars !! 29) (chars !! 25) == 100 then do
                                                if (.|.) (chars !! 16) (chars !! 29) == 127 then do
                                                    if (-) (chars !! 20) (chars !! 6) == -8 then do
                                                        if (+) (chars !! 21) (chars !! 20) == 197 then do
                                                            if (+) (chars !! 2) (chars !! 36) == 77 then do
                                                                if (*) (chars !! 35) (chars !! 11) == 3630 then do
                                                                    if (*) (chars !! 4) (chars !! 3) == 2714 then do
                                                                        if xor (chars !! 35) (chars !! 6) == 72 then do
                                                                            if (+) (chars !! 25) (chars !! 24) == 221 then do
                                                                                if (*) (chars !! 14) (chars !! 36) == 3465 then do
                                                                                    if (-) ((-) (chars !! 15) (chars !! 11)) 148 == -156 then do
                                                                                        if (+) (chars !! 37) (chars !! 17) == 138 then do
                                                                                            if xor (chars !! 1) (chars !! 38) == 70 then do
                                                                                                if (+) (chars !! 9) (chars !! 29) == 212 then do
                                                                                                    if (-) (chars !! 30) (chars !! 10) == 7 then do
                                                                                                        if (+) (chars !! 10) (chars !! 33) == 206 then do
                                                                                                            if (*) (chars !! 7) (chars !! 15) == 11118 then do
                                                                                                                if (*) ((*) (chars !! 28) (chars !! 14)) 55 == 641025 then do
                                                                                                                    if (.|.) ((.|.) (chars !! 7) (chars !! 4)) 216 == 255 then do
                                                                                                                        if (+) (chars !! 24) (chars !! 4) == 151 then do
                                                                                                                            if (*) (chars !! 2) (chars !! 30) == 4928 then do
                                                                                                                                if (+) (chars !! 5) (chars !! 22) == 224 then do
                                                                                                                                    if (.|.) (chars !! 18) (chars !! 36) == 127 then do
                                                                                                                                        if (+) (chars !! 13) (chars !! 34) == 195 then do
                                                                                                                                            if (.|.) (chars !! 9) (chars !! 17) == 111 then do
                                                                                                                                                if (*) (chars !! 12) (chars !! 9) == 10403 then do
                                                                                                                                                    if xor (chars !! 25) (chars !! 27) == 23 then do
                                                                                                                                                        if xor (chars !! 13) (chars !! 34) == 59 then do
                                                                                                                                                            if (+) (chars !! 18) (chars !! 31) == 200 then do
                                                                                                                                                                if (+) (chars !! 17) (chars !! 32) == 213 then do
                                                                                                                                                                    if (*) (chars !! 2) (chars !! 12) == 4444 then do
                                                                                                                                                                        if (*) (chars !! 24) (chars !! 31) == 11025 then do
                                                                                                                                                                            if (*) (chars !! 5) (chars !! 0) == 5658 then do
                                                                                                                                                                                if (+) ((+) (chars !! 10) (chars !! 32)) 228 == 441 then do
                                                                                                                                                                                    if (*) (chars !! 35) (chars !! 0) == 1518 then do
                                                                                                                                                                                        if (.|.) (chars !! 30) (chars !! 8) == 113 then do
                                                                                                                                                                                            if (-) (chars !! 28) (chars !! 34) == 11 then do
                                                                                                                                                                                                if (*) (chars !! 26) (chars !! 14) == 9975 then do
                                                                                                                                                                                                    if (*) (chars !! 31) (chars !! 22) == 10605 then do
                                                                                                                                                                                                        if (*) ((*) (chars !! 26) (chars !! 32)) 239 == 2452140 then do
                                                                                                                                                                                                            if (*) (chars !! 28) (chars !! 38) == 13875 then do
                                                                                                                                                                                                                if (+) (chars !! 18) (chars !! 16) == 190 then do
                                                                                                                                                                                                                    if (+) ((+) (chars !! 27) (chars !! 26)) 96 == 290 then do
                                                                                                                                                                                                                        if (-) (chars !! 22) (chars !! 38) == -24 then do
                                                                                                                                                                                                                            if (+) (chars !! 33) (chars !! 5) == 224 then do
                                                                                                                                                                                                                                if (*) (chars !! 19) (chars !! 16) == 10355 then do
                                                                                                                                                                                                                                    if (+) (chars !! 27) (chars !! 1) == 158 then do
                                                                                                                                                                                                                                        if (+) (chars !! 33) (chars !! 12) == 202 then do
                                                                                                                                                                                                                                            if (*) (chars !! 19) (chars !! 23) == 10355 then do
                                                                                                                                                                                                                                                putStrLn "yea go submit the flag"
                                                                                                                                                                                                                                                exitSuccess
                                                                                                                                                                                                                                            else do
                                                                                                                                                                                                                                                putStrLn "no thats not 10355"
                                                                                                                                                                                                                                                exitFailure
                                                                                                                                                                                                                                        else do
                                                                                                                                                                                                                                            putStrLn "no thats not 202"
                                                                                                                                                                                                                                            exitFailure
                                                                                                                                                                                                                                    else do
                                                                                                                                                                                                                                        putStrLn "no thats not 158"
                                                                                                                                                                                                                                        exitFailure
                                                                                                                                                                                                                                else do
                                                                                                                                                                                                                                    putStrLn "no thats not 10355"
                                                                                                                                                                                                                                    exitFailure
                                                                                                                                                                                                                            else do
                                                                                                                                                                                                                                putStrLn "no thats not 224"
                                                                                                                                                                                                                                exitFailure
                                                                                                                                                                                                                        else do
                                                                                                                                                                                                                            putStrLn "no thats not -24"
                                                                                                                                                                                                                            exitFailure
                                                                                                                                                                                                                    else do
                                                                                                                                                                                                                        putStrLn "no thats not 290"
                                                                                                                                                                                                                        exitFailure
                                                                                                                                                                                                                else do
                                                                                                                                                                                                                    putStrLn "no thats not 190"
                                                                                                                                                                                                                    exitFailure
                                                                                                                                                                                                            else do
                                                                                                                                                                                                                putStrLn "no thats not 13875"
                                                                                                                                                                                                                exitFailure
                                                                                                                                                                                                        else do
                                                                                                                                                                                                            putStrLn "no thats not 2452140"
                                                                                                                                                                                                            exitFailure
                                                                                                                                                                                                    else do
                                                                                                                                                                                                        putStrLn "no thats not 10605"
                                                                                                                                                                                                        exitFailure
                                                                                                                                                                                                else do
                                                                                                                                                                                                    putStrLn "no thats not 9975"
                                                                                                                                                                                                    exitFailure
                                                                                                                                                                                            else do
                                                                                                                                                                                                putStrLn "no thats not 11"
                                                                                                                                                                                                exitFailure
                                                                                                                                                                                        else do
                                                                                                                                                                                            putStrLn "no thats not 113"
                                                                                                                                                                                            exitFailure
                                                                                                                                                                                    else do
                                                                                                                                                                                        putStrLn "no thats not 1518"
                                                                                                                                                                                        exitFailure
                                                                                                                                                                                else do
                                                                                                                                                                                    putStrLn "no thats not 441"
                                                                                                                                                                                    exitFailure
                                                                                                                                                                            else do
                                                                                                                                                                                putStrLn "no thats not 5658"
                                                                                                                                                                                exitFailure
                                                                                                                                                                        else do
                                                                                                                                                                            putStrLn "no thats not 11025"
                                                                                                                                                                            exitFailure
                                                                                                                                                                    else do
                                                                                                                                                                        putStrLn "no thats not 4444"
                                                                                                                                                                        exitFailure
                                                                                                                                                                else do
                                                                                                                                                                    putStrLn "no thats not 213"
                                                                                                                                                                    exitFailure
                                                                                                                                                            else do
                                                                                                                                                                putStrLn "no thats not 200"
                                                                                                                                                                exitFailure
                                                                                                                                                        else do
                                                                                                                                                            putStrLn "no thats not 59"
                                                                                                                                                            exitFailure
                                                                                                                                                    else do
                                                                                                                                                        putStrLn "no thats not 23"
                                                                                                                                                        exitFailure
                                                                                                                                                else do
                                                                                                                                                    putStrLn "no thats not 10403"
                                                                                                                                                    exitFailure
                                                                                                                                            else do
                                                                                                                                                putStrLn "no thats not 111"
                                                                                                                                                exitFailure
                                                                                                                                        else do
                                                                                                                                            putStrLn "no thats not 195"
                                                                                                                                            exitFailure
                                                                                                                                    else do
                                                                                                                                        putStrLn "no thats not 127"
                                                                                                                                        exitFailure
                                                                                                                                else do
                                                                                                                                    putStrLn "no thats not 224"
                                                                                                                                    exitFailure
                                                                                                                            else do
                                                                                                                                putStrLn "no thats not 4928"
                                                                                                                                exitFailure
                                                                                                                        else do
                                                                                                                            putStrLn "no thats not 151"
                                                                                                                            exitFailure
                                                                                                                    else do
                                                                                                                        putStrLn "no thats not 255"
                                                                                                                        exitFailure
                                                                                                                else do
                                                                                                                    putStrLn "no thats not 641025"
                                                                                                                    exitFailure
                                                                                                            else do
                                                                                                                putStrLn "no thats not 11118"
                                                                                                                exitFailure
                                                                                                        else do
                                                                                                            putStrLn "no thats not 206"
                                                                                                            exitFailure
                                                                                                    else do
                                                                                                        putStrLn "no thats not 7"
                                                                                                        exitFailure
                                                                                                else do
                                                                                                    putStrLn "no thats not 212"
                                                                                                    exitFailure
                                                                                            else do
                                                                                                putStrLn "no thats not 70"
                                                                                                exitFailure
                                                                                        else do
                                                                                            putStrLn "no thats not 138"
                                                                                            exitFailure
                                                                                    else do
                                                                                        putStrLn "no thats not -156"
                                                                                        exitFailure
                                                                                else do
                                                                                    putStrLn "no thats not 3465"
                                                                                    exitFailure
                                                                            else do
                                                                                putStrLn "no thats not 221"
                                                                                exitFailure
                                                                        else do
                                                                            putStrLn "no thats not 72"
                                                                            exitFailure
                                                                    else do
                                                                        putStrLn "no thats not 2714"
                                                                        exitFailure
                                                                else do
                                                                    putStrLn "no thats not 3630"
                                                                    exitFailure
                                                            else do
                                                                putStrLn "no thats not 77"
                                                                exitFailure
                                                        else do
                                                            putStrLn "no thats not 197"
                                                            exitFailure
                                                    else do
                                                        putStrLn "no thats not -8"
                                                        exitFailure
                                                else do
                                                    putStrLn "no thats not 127"
                                                    exitFailure
                                            else do
                                                putStrLn "no thats not 100"
                                                exitFailure
                                        else do
                                            putStrLn "no thats not 11990"
                                            exitFailure
                                    else do
                                        putStrLn "no thats not 105"
                                        exitFailure
                                else do
                                    putStrLn "no thats not 5723"
                                    exitFailure
                            else do
                                putStrLn "no thats not 159"
                                exitFailure
                        else do
                            putStrLn "no thats not 2714"
                            exitFailure
                    else do
                        putStrLn "no thats not 9215"
                        exitFailure
                else do
                    putStrLn "no thats not 197"
                    exitFailure
            else do
                putStrLn "no thats not 3366"
                exitFailure


main :: IO ()
main = do
    args <- getArgs
    case args of
        [flag] -> checkFlag flag
        _      -> do
            putStrLn "yo u gotta pass in a flag bruh or else the case args thing won't match the first case"