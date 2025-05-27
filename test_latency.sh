#!/bin/bash
# filepath: /home/julia/Course/SSDI/XDP-Load-Balancer-with-DSR/test_latency.sh

clients=(client-test1 client-test2 client-test3)
target_ip=10.10.0.5

# for c in "${clients[@]}"; do
#   docker exec $c sh -c "
#     for i in \$(seq 1 1000); do
#       curl -o /dev/null -s -w '%{time_total}\n' http://$target_ip:80/cpu &
#       if (( i % 100 == 0 )); then
#         wait
#       fi
#     done
#     wait
#   " > ${c}_latency_cpu.txt &
# done

# wait

for c in "${clients[@]}"; do
  docker exec $c sh -c "for i in \$(seq 1 1000); do curl -o /dev/null -s -w '%{time_total}\n' http://$target_ip:80/cpu; done" > ${c}_latency_cpu.txt &
done

wait

cat client*_latency_cpu.txt | awk '{sum+=$1} END {print "平均 cpu latency:", sum/NR, "秒"}'

for c in "${clients[@]}"; do
  docker exec $c sh -c "for i in \$(seq 1 50); do curl -o /dev/null -s -w '%{time_total}\n' http://$target_ip:80/io; done" > ${c}_latency_io.txt &
done

wait

cat client*_latency_io.txt | awk '{sum+=$1} END {print "平均 io latency:", sum/NR, "秒"}'s