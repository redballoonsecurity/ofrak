entry byte_histogram [n] (xs: [n]u8): [256]i64 =
  hist (+) 0 256 (map i64.u8 xs) (replicate n 1)

entry entropy [n] (xs: [n]u8): f32 =
  (byte_histogram xs)
    |> map (\x -> f32.i64(x) / (f32.i64 n))
    |> map (\x -> if x == 0.0 then 0.0 else x * (f32.log2 x))
    |> reduce (+) 0.0
    |> \x -> -1.0 * x / (f32.log2 (f32.i64 n))

entry chunked_entropy [n] (chunk_size: i64) (xs: [n]u8) =
  (0..<(n / chunk_size))
    |> map (\i -> u8.f32(f32.floor(entropy(xs[i * chunk_size:(i + 1) * chunk_size]) * 255)))
