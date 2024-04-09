entry byte_histogram [n] (xs: [n]u8): [256]i64 =
  hist (+) 0 256 (map i64.u8 xs) (replicate n 1)

entry entropy [n] (xs: [n]u8): f32 =
  (byte_histogram xs)
    |> map f32.i64
    |> map (/ (f32.i64 n))
    |> map (\x -> if x == 0.0 then 0.0 else x * (f32.log2 x))
    |> reduce (+) 0.0
    |> \x -> -1.0 * x / (f32.log2 (f32.i64 n))

entry chunked_entropy [n] (chunk_size: i64) (xs: [n]u8) =
  (1...(n / chunk_size) - 1)
    |> map (\i -> entropy(xs[i * chunk_size:(i + 1) * chunk_size]))
