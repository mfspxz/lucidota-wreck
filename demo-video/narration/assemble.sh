#!/usr/bin/env bash
# Assemble timed narration track: each section starts at its still's timestamp.
# Usage: assemble.sh  (runs in narration/ dir)
set -euo pipefail
cd "$(dirname "$0")"

# section start times in seconds (from demo-video/concat.txt cumulative durations)
declare -A START=(
  [n01]=0   [n02]=10  [n03]=24  [n04]=42  [n05]=60
  [n06]=82  [n07]=88  [n08]=106 [n09]=132 [n10]=150
  [n11]=162 [n12]=178 [n13]=192 [n14]=212 [n15]=234
  [n16]=240 [n17]=262 [n18]=274 [n19]=298 [n20]=322
)
ORDER="n01 n02 n03 n04 n05 n06 n07 n08 n09 n10 n11 n12 n13 n14 n15 n16 n17 n18 n19 n20"

# slot durations (each section's still duration)
declare -A SLOT=(
  [n01]=10  [n02]=14  [n03]=18  [n04]=18  [n05]=22
  [n06]=6   [n07]=18  [n08]=26  [n09]=18  [n10]=12
  [n11]=16  [n12]=14  [n13]=20  [n14]=22  [n15]=6
  [n16]=22  [n17]=12  [n18]=24  [n19]=24  [n20]=14
)

for s in $ORDER; do
  [ -f "$s.mp3" ] || { echo "MISSING $s.mp3"; exit 1; }
  dur=$(ffprobe -hide_banner -v error -show_entries format=duration -of csv=p=0 "$s.mp3")
  slot=${SLOT[$s]}
  over=$(python3 -c "print('OVER' if $dur > $slot else 'ok')")
  echo "$s dur=${dur}s slot=${slot}s -> $over"
done

# Build filter: delay each section to its start time, then mix.
inputs=""; filter=""
i=0
for s in $ORDER; do
  inputs="$inputs -i $s.mp3"
  filter="${filter}[$i:a]adelay=${START[$s]}000|${START[$s]}000[a$i];"
  i=$((i+1))
done
mix=""
for j in $(seq 0 19); do mix="${mix}[a$j]"; done

ffmpeg -hide_banner -y $inputs -filter_complex \
  "${filter}${mix}amix=inputs=20:normalize=0[aout]" \
  -map "[aout]" -c:a libmp3lame -b:a 128k narration-track.mp3
echo "wrote narration-track.mp3"
ffprobe -hide_banner narration-track.mp3 2>&1 | grep Duration

# Mux with the draft video (video stream copied, no re-encode)
ffmpeg -hide_banner -y -i ../wreck-demo-draft-2026-10-13.mp4 -i narration-track.mp3 \
  -c:v copy -c:a aac -b:a 128k -shortest \
  wreck-demo-final-2026-10-14.mp4
echo "wrote wreck-demo-final-2026-10-14.mp4"
ffprobe -hide_banner wreck-demo-final-2026-10-14.mp4 2>&1 | grep -E "Duration|Stream"
