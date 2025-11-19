#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"
TEST_DIR="$PROJECT_ROOT/build/tests"
NUM_TRIALS=10

mkdir -p "$SCRIPT_DIR/experimental_results/mehp24"
mkdir -p "$SCRIPT_DIR/experimental_results/ours"
mkdir -p "$SCRIPT_DIR/experimental_results/ours_hybrid"
mkdir -p "$SCRIPT_DIR/experimental_results/kway_k2"
mkdir -p "$SCRIPT_DIR/experimental_results/kway_k3"
mkdir -p "$SCRIPT_DIR/experimental_results/kway_k5"

DIRECT_SIZES=(4 8 16 32 64 128 256 512 1024)
MEHP24_SIZES=(4 8 16 32 64 128 256 512 1024)
KWAY_K2_SIZES=(4 8 16 32 64 128 256 512 1024)
KWAY_K3_SIZES=(9 27 81 243 729)
KWAY_K5_SIZES=(25 125 625)

extract_test_results() {
    local input_file=$1
    local output_dir=$2

    local sizes=($(grep "^Input array size:" "$input_file" | awk '{print $4}'))

    if [ ${#sizes[@]} -eq 0 ]; then
        echo "Warning: No 'Input array size:' patterns found in $input_file"
        cat "$input_file" > "${output_dir}/debug_output.txt"
        echo "Saved test output to ${output_dir}/debug_output.txt for debugging"
        return
    fi

    for i in "${!sizes[@]}"; do
        local size=${sizes[$i]}
        echo "Processing results for size: $size"

        local size_file="${output_dir}/size_${size}.txt"
        > "$size_file"

        local start_pattern="Input array size: ${size}"

        if [ $((i+1)) -lt ${#sizes[@]} ]; then
            local next_size=${sizes[$((i+1))]}
            local end_pattern="Input array size: ${next_size}"

            awk -v start="$start_pattern" -v end="$end_pattern" '
                $0 ~ start {found=1; print; next}
                $0 ~ end {found=0}
                found {print}
            ' "$input_file" > "$size_file"
        else
            awk -v start="$start_pattern" '
                $0 ~ start {found=1}
                found {print}
            ' "$input_file" > "$size_file"
        fi
    done
}

format_results() {
    local algo=$1
    local size=$2
    local trial_dir=$3
    local summary_file="${SCRIPT_DIR}/experimental_results/${algo}/N${size}_summary.txt"
    local total_file="${SCRIPT_DIR}/experimental_results/${algo}/total_results.txt"

    > "$summary_file"

    local ring_dim=""
    local mult_depth=""
    local scale_mod=""
    local sign_config=""
    local times=()
    local max_err_logs=()
    local avg_err_logs=()
    local idle_mems=()
    local setup_mems=()
    local peak_mems=()
    local avg_mems=()
    local crypto_overhead_mems=()
    local sorting_overhead_mems=()

    local found_results=false

    for trial in $(seq 1 $NUM_TRIALS); do
        local result_file="${trial_dir}/trial_${trial}/size_${size}.txt"
        if [[ -f "$result_file" && -s "$result_file" ]]; then
            found_results=true

            if [[ -z "$ring_dim" ]]; then
                ring_dim=$(grep -m1 "Using Ring Dimension:" "$result_file" | awk '{print $4}')
                mult_depth=$(grep -m1 "Multiplicative depth:" "$result_file" | awk '{print $3}')
                scale_mod=$(grep -m1 "Scaling Mod:" "$result_file" | awk '{print $3}')

                sign_config_line=$(grep -m1 "Sign Configuration:" "$result_file" 2>/dev/null)

                if [[ -n "$sign_config_line" ]]; then
                    sign_config=$(echo "$sign_config_line" | sed 's/Sign Configuration: //')
                else
                    sign_config="Not Found"
                fi

                ring_dim=${ring_dim:-"N/A"}
                mult_depth=${mult_depth:-"N/A"}
                scale_mod=${scale_mod:-"N/A"}
            fi

            local time=$(grep -m1 "Execution time:" "$result_file" | awk '{print $3}')
            local max_err_log=$(grep -m1 "Maximum error:" "$result_file" | awk -F'log2: ' '{print $2}' | tr -d ')')
            local avg_err_log=$(grep -m1 "Average error:" "$result_file" | awk -F'log2: ' '{print $2}' | tr -d ')')

            local idle_mem=$(grep -m1 "Idle Memory (GB):" "$result_file" | awk '{print $4}')
            local setup_mem=$(grep -m1 "Setup Memory (GB):" "$result_file" | awk '{print $4}')
            local peak_mem=$(grep -m1 "Peak Memory (GB):" "$result_file" | awk '{print $4}')
            local avg_mem=$(grep -m1 "Average Memory (GB):" "$result_file" | awk '{print $4}')
            local crypto_overhead_mem=$(grep -m1 "Crypto Overhead (GB):" "$result_file" | awk '{print $4}')
            local sorting_overhead_mem=$(grep -m1 "Sorting Overhead (GB):" "$result_file" | awk '{print $4}')

            if [[ "$max_err_log" != "N/A" && "$max_err_log" =~ ^-?[0-9]+(\.[0-9]+)?$ ]]; then
                max_err_logs+=($max_err_log)
            fi

            if [[ "$avg_err_log" != "N/A" && "$avg_err_log" =~ ^-?[0-9]+(\.[0-9]+)?$ ]]; then
                avg_err_logs+=($avg_err_log)
            fi

            if [[ -n "$time" ]]; then
                times+=($time)
            fi

            if [[ -n "$idle_mem" && "$idle_mem" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
                idle_mems+=($idle_mem)
            fi
            if [[ -n "$setup_mem" && "$setup_mem" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
                setup_mems+=($setup_mem)
            fi
            if [[ -n "$peak_mem" && "$peak_mem" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
                peak_mems+=($peak_mem)
            fi
            if [[ -n "$avg_mem" && "$avg_mem" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
                avg_mems+=($avg_mem)
            fi
            if [[ -n "$crypto_overhead_mem" && "$crypto_overhead_mem" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
                crypto_overhead_mems+=($crypto_overhead_mem)
            fi
            if [[ -n "$sorting_overhead_mem" && "$sorting_overhead_mem" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
                sorting_overhead_mems+=($sorting_overhead_mem)
            fi
        fi
    done

    if [[ "$found_results" == "false" ]]; then
        echo "No valid results found for $algo with N=$size"
        return
    fi

    local n_trials=${#times[@]}
    if [[ $n_trials -eq 0 ]]; then
        echo "No timing data found for $algo with N=$size"
        return
    fi

    local avg_time="N/A"
    local avg_max_err_log="N/A"
    local avg_avg_err_log="N/A"
    local avg_idle_mem="N/A"
    local avg_setup_mem="N/A"
    local avg_peak_mem="N/A"
    local avg_avg_mem="N/A"
    local avg_crypto_overhead_mem="N/A"
    local avg_sorting_overhead_mem="N/A"

    if [[ $n_trials -gt 0 ]]; then
        local total_time=0
        for t in "${times[@]}"; do
            total_time=$(echo "$total_time + $t" | bc -l)
        done
        avg_time=$(echo "scale=4; $total_time / $n_trials / 1000" | bc -l)

        if [[ -z "$avg_time" || "$avg_time" == "0" ]]; then
            avg_time="N/A"
        fi
    fi

    if [[ ${#max_err_logs[@]} -gt 0 ]]; then
        local log_sum=0
        for log_val in "${max_err_logs[@]}"; do
            log_sum=$(echo "$log_sum + $log_val" | bc -l)
        done
        avg_max_err_log=$(echo "scale=4; $log_sum / ${#max_err_logs[@]}" | bc -l)
    fi

    if [[ ${#avg_err_logs[@]} -gt 0 ]]; then
        local log_sum=0
        for log_val in "${avg_err_logs[@]}"; do
            log_sum=$(echo "$log_sum + $log_val" | bc -l)
        done
        avg_avg_err_log=$(echo "scale=4; $log_sum / ${#avg_err_logs[@]}" | bc -l)
    fi

    if [[ ${#idle_mems[@]} -gt 0 ]]; then
        local mem_sum=0
        for mem_val in "${idle_mems[@]}"; do
            mem_sum=$(echo "$mem_sum + $mem_val" | bc -l)
        done
        avg_idle_mem=$(echo "scale=4; $mem_sum / ${#idle_mems[@]}" | bc -l)
    fi

    if [[ ${#setup_mems[@]} -gt 0 ]]; then
        local mem_sum=0
        for mem_val in "${setup_mems[@]}"; do
            mem_sum=$(echo "$mem_sum + $mem_val" | bc -l)
        done
        avg_setup_mem=$(echo "scale=4; $mem_sum / ${#setup_mems[@]}" | bc -l)
    fi

    if [[ ${#peak_mems[@]} -gt 0 ]]; then
        local mem_sum=0
        for mem_val in "${peak_mems[@]}"; do
            mem_sum=$(echo "$mem_sum + $mem_val" | bc -l)
        done
        avg_peak_mem=$(echo "scale=4; $mem_sum / ${#peak_mems[@]}" | bc -l)
    fi

    if [[ ${#avg_mems[@]} -gt 0 ]]; then
        local mem_sum=0
        for mem_val in "${avg_mems[@]}"; do
            mem_sum=$(echo "$mem_sum + $mem_val" | bc -l)
        done
        avg_avg_mem=$(echo "scale=4; $mem_sum / ${#avg_mems[@]}" | bc -l)
    fi

    if [[ ${#crypto_overhead_mems[@]} -gt 0 ]]; then
        local mem_sum=0
        for mem_val in "${crypto_overhead_mems[@]}"; do
            mem_sum=$(echo "$mem_sum + $mem_val" | bc -l)
        done
        avg_crypto_overhead_mem=$(echo "scale=4; $mem_sum / ${#crypto_overhead_mems[@]}" | bc -l)
    fi

    if [[ ${#sorting_overhead_mems[@]} -gt 0 ]]; then
        local mem_sum=0
        for mem_val in "${sorting_overhead_mems[@]}"; do
            mem_sum=$(echo "$mem_sum + $mem_val" | bc -l)
        done
        avg_sorting_overhead_mem=$(echo "scale=4; $mem_sum / ${#sorting_overhead_mems[@]}" | bc -l)
    fi

    echo "======================================" > "$summary_file"
    echo "     Results for N = $size" >> "$summary_file"
    echo "======================================" >> "$summary_file"
    echo "Crypto Parameters:" >> "$summary_file"
    echo "  Ring Dimension      : $ring_dim" >> "$summary_file"
    echo "  Multiplicative Depth: $mult_depth" >> "$summary_file"
    echo "  Scaling Mod Size    : $scale_mod" >> "$summary_file"
    echo "  Sign Configuration  : $sign_config" >> "$summary_file"
    echo "" >> "$summary_file"
    echo "Performance Metrics:" >> "$summary_file"
    echo "  Average Time     : ${avg_time}s" >> "$summary_file"
    echo "" >> "$summary_file"
    echo "Memory Metrics:" >> "$summary_file"
    echo "  Idle Memory        : ${avg_idle_mem} GB" >> "$summary_file"
    echo "  Setup Memory       : ${avg_setup_mem} GB" >> "$summary_file"
    echo "  Peak Memory        : ${avg_peak_mem} GB" >> "$summary_file"
    echo "  Average Memory     : ${avg_avg_mem} GB" >> "$summary_file"
    echo "  Crypto Overhead    : ${avg_crypto_overhead_mem} GB" >> "$summary_file"
    echo "  Sorting Overhead   : ${avg_sorting_overhead_mem} GB" >> "$summary_file"
    echo "" >> "$summary_file"
    echo "Error Analysis:" >> "$summary_file"
    echo "  Max Error (log2): $avg_max_err_log" >> "$summary_file"
    echo "  Average Error (log2): $avg_avg_err_log" >> "$summary_file"
    echo "======================================" >> "$summary_file"

    cat "$summary_file" >> "$total_file"
    echo "" >> "$total_file"

    echo "Results for $algo with N=$size successfully processed"
}

run_test() {
   local algo=$1
   local test_executable=$2
   local sizes=("${@:3}")

   echo "Running $algo tests"
   cd "$TEST_DIR" || exit 1

   for trial in $(seq 1 $NUM_TRIALS); do
       echo "Trial $trial of $NUM_TRIALS"
       local trial_output_dir="${SCRIPT_DIR}/experimental_results/${algo}/trials/trial_${trial}"
       mkdir -p "$trial_output_dir"

       local executable_path="./$test_executable"

       echo "Executing: $executable_path"
       sync

       if [[ "$algo" == "kway_k2" || "$algo" == "kway_k3" || "$algo" == "kway_k5" ]]; then
           $executable_path --gtest_filter="KWaySortTestFixture/*.SortTest" > "${trial_output_dir}/output.txt" 2>&1
       else
           $executable_path > "${trial_output_dir}/output.txt" 2>&1
       fi

       if [ $? -ne 0 ]; then
           echo "Warning: Process exited with error for $algo"
           cat "${trial_output_dir}/output.txt" > "${trial_output_dir}/error_output.txt"
           echo "Error output saved to ${trial_output_dir}/error_output.txt"
       fi

       extract_test_results "${trial_output_dir}/output.txt" "$trial_output_dir"

       sync
       sleep 10
   done

   local trial_dir="${SCRIPT_DIR}/experimental_results/${algo}/trials"
   for size in "${sizes[@]}"; do
       format_results "$algo" "$size" "$trial_dir"
   done
}

mkdir -p "${SCRIPT_DIR}/experimental_results/ours_hybrid/trials"
mkdir -p "${SCRIPT_DIR}/experimental_results/mehp24/trials"
mkdir -p "${SCRIPT_DIR}/experimental_results/ours/trials"
mkdir -p "${SCRIPT_DIR}/experimental_results/kway_k2/trials"
mkdir -p "${SCRIPT_DIR}/experimental_results/kway_k3/trials"
mkdir -p "${SCRIPT_DIR}/experimental_results/kway_k5/trials"

> "${SCRIPT_DIR}/experimental_results/ours_hybrid/total_results.txt"
> "${SCRIPT_DIR}/experimental_results/mehp24/total_results.txt"
> "${SCRIPT_DIR}/experimental_results/ours/total_results.txt"
> "${SCRIPT_DIR}/experimental_results/kway_k2/total_results.txt"
> "${SCRIPT_DIR}/experimental_results/kway_k3/total_results.txt"
> "${SCRIPT_DIR}/experimental_results/kway_k5/total_results.txt"

run_test "kway_k2" "k-way/KWaySort2Test" "${KWAY_K2_SIZES[@]}"
sync
sleep 30
run_test "kway_k3" "k-way/KWaySort3Test" "${KWAY_K3_SIZES[@]}"
sync
sleep 30
run_test "kway_k5" "k-way/KWaySort5Test" "${KWAY_K5_SIZES[@]}"

# sync
# sleep 30
# run_test "ours" "DirectSortTest" "${DIRECT_SIZES[@]}"

# sync
# sleep 30
# run_test "mehp24" "mehp24/Mehp24SortTest" "${MEHP24_SIZES[@]}"

# sync
# sleep 30
# run_test "ours_hybrid" "DirectSortHTest" "${DIRECT_SIZES[@]}"

# generate_final_summary

echo "KWay experiments completed!"
