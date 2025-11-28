#!/bin/bash

# ==========================================================
# BUG HUNTER ADVANCED (v5.0 - Enterprise Edition)
# ==========================================================

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
PURPLE='\033[1;35m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# --- Variabel Global dan Konfigurasi State ---
CONFIG_FILE="bh_config.cfg"
RESULT_DIR="results_$(date +%Y%m%d_%H%M%S)"
RESULT_200="${RESULT_DIR}/200_ok.txt"
RESULT_VULN="${RESULT_DIR}/vulnerability_alerts.txt"
LOG_FILE="${RESULT_DIR}/all_responses.log"
BASELINE_CACHE_FILE="${RESULT_DIR}/baseline_cache.tmp"
DEFAULT_USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36 BugHunterBot/5.0-Enterprise"

# Default Settings
THREAD_COUNT=15
PROXY_URL=""
CURL_TIMEOUT=15
FOLLOW_REDIRECTS=true
SILENT_MODE=false
SIZE_DELTA_THRESHOLD=150 # Ukuran byte perbedaan dianggap anomali
TIME_DELTA_FACTOR=5      # Faktor perlambatan waktu dianggap anomali (misal, 5x baseline)

CUSTOM_METHOD="GET"
CUSTOM_DATA=""
CUSTOM_HEADERS=()
FUZZ_MODE=false
FUZZ_PAYLOAD_FILE=""
FUZZ_HEADER_NAME=""
GREP_STRING=""

# --- Fungsi Manajemen Konfigurasi ---

save_config() {
    echo "THREAD_COUNT=$THREAD_COUNT" > "$CONFIG_FILE"
    echo "PROXY_URL=$PROXY_URL" >> "$CONFIG_FILE"
    echo "CURL_TIMEOUT=$CURL_TIMEOUT" >> "$CONFIG_FILE"
    echo "FOLLOW_REDIRECTS=$FOLLOW_REDIRECTS" >> "$CONFIG_FILE"
    echo "SILENT_MODE=$SILENT_MODE" >> "$CONFIG_FILE"
    echo "SIZE_DELTA_THRESHOLD=$SIZE_DELTA_THRESHOLD" >> "$CONFIG_FILE"
    echo "TIME_DELTA_FACTOR=$TIME_DELTA_FACTOR" >> "$CONFIG_FILE"
    echo "CUSTOM_METHOD=$CUSTOM_METHOD" >> "$CONFIG_FILE"
    echo "CUSTOM_DATA=\"$CUSTOM_DATA\"" >> "$CONFIG_FILE"
    echo "FUZZ_MODE=$FUZZ_MODE" >> "$CONFIG_FILE"
    echo "FUZZ_PAYLOAD_FILE=$FUZZ_PAYLOAD_FILE" >> "$CONFIG_FILE"
    echo "FUZZ_HEADER_NAME=$FUZZ_HEADER_NAME" >> "$CONFIG_FILE"
    echo "GREP_STRING=\"$GREP_STRING\"" >> "$CONFIG_FILE"
    
    # Simpan array CUSTOM_HEADERS (Perbaikan sanitasi input)
    # Gunakan 'printf' untuk memastikan setiap elemen diapit kutip ganda dan dipisahkan spasi
    local header_list
    header_list=$(printf '"%s" ' "${CUSTOM_HEADERS[@]}")
    echo "CUSTOM_HEADERS=($header_list)" >> "$CONFIG_FILE"
    
    echo -e "${GREEN}[+] Konfigurasi disimpan ke ${CONFIG_FILE}${NC}"
}

load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        # Menggunakan source untuk memuat variabel dari file konfigurasi
        source "$CONFIG_FILE"
        echo -e "${GREEN}[+] Konfigurasi dimuat dari ${CONFIG_FILE}${NC}"
    fi
}

# --- Fungsi Pengecekan dan Banner ---

show_banner() {
    echo -e "${RED}
  ██▓ ███▄ ▄███▓ ██▓ ███▄    █  ▄▄▄      ██████  
 ▓██▒▓██▒▀█▀ ██▒▓██▒ ██ ▀█    █ ▒████▄   ▒██    ▒ 
 ▒██▒▓██  ▓██░▒██▒▓██  ▀█ ██▒▒██ ▀█▄ ░ ▓██▄    
 ░██░▒██  ▒██ ░██░▓██▒ ▐▌██▒░██▄▄▄▄██  ▒ ██▒
 ░██░▒██▒ ░██▒░██░▒██░ ▓██░ ▓█ ▓██▒██████▒▒
 ░▓  ░ ▒░ ░  ░░▓  ░ ▒░ ▒ ▒  ▒▒ ▓▒█▒ ▒▓▒ ▒ ░
  ▒ ░░  ░  ░  ▒ ░░ ░░  ░ ▒░  ▒ ▒▒ ░ ░▒  ░ ░
  ▒ ░░    ░  ▒ ░ ░   ░ ░   ░ ▒  ░  ░ 
  ░           ░     ░ ░      ░
${NC}"
    echo -e "${CYAN}Created by: El Doree - Payload Tester v5.0 (Enterprise Edition)${NC}"
    echo -e "${YELLOW}Smart Baseline Caching & Advanced Anomaly Detection${NC}"
    echo ""
}

check_dependencies() {
    echo -e "${CYAN}[+] Memulai Inisialisasi Tool...${NC}"
    
    if ! command -v curl &> /dev/null; then
        echo -e "${RED}[!] 'curl' tidak terinstall! Tool ini memerlukannya. Harap install secara manual.${NC}"
        exit 1
    fi
    if ! command -v bc &> /dev/null; then
        echo -e "${RED}[!] 'bc' (basic calculator) tidak terinstall! Diperlukan untuk Time Delta. Harap install secara manual.${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}[+] Dependencies (curl, bc) OK.${NC}"

    mkdir -p "$RESULT_DIR" 2>/dev/null
    mkdir -p "$RESULT_DIR/full_responses" 2>/dev/null
    echo -e "${YELLOW}[+] Hasil akan disimpan di direktori: ${RESULT_DIR}${NC}"
}

# Fungsi Pembantu untuk Fuzzing: Mengambil Baseline dari Cache
get_baseline() {
    local url_key=$(echo "$1" | md5sum 2>/dev/null | awk '{print $1}')
    grep "^$url_key" "$BASELINE_CACHE_FILE" 2>/dev/null | awk '{print $2 " " $3}'
}

# --- Fungsi Inti Scanning ---

scan_single() {
    # Amankan semua input dari subshell atau command injection
    local url="$1"
    local custom_header_key="$2"
    local custom_header_value="$3"
    
    local output_format='%{http_code} %{size_download} %{time_total}\n'
    # Gunakan md5sum untuk membuat ID unik respons (memerlukan md5sum/md5)
    local unique_id=$(echo "$url$custom_header_key$custom_header_value" | md5sum 2>/dev/null | awk '{print $1}')
    local response_header_file="${RESULT_DIR}/full_responses/${unique_id}_header.txt"
    local response_body_file="${RESULT_DIR}/full_responses/${unique_id}_body.txt"
    local log_prefix=""
    
    if [ -n "$custom_header_key" ]; then
        log_prefix="[FUZZ:${custom_header_key}:${custom_header_value}]"
    fi

    if [[ ! "$url" =~ ^https?:// ]]; then
        url="http://$url"
    fi

    CURL_OPTS=(
        -s -k -m "$CURL_TIMEOUT"
        -A "$DEFAULT_USER_AGENT"
        -o "$response_body_file"
        -D "$response_header_file"
        -w "$output_format"
        -X "$CUSTOM_METHOD"
    )

    if [ "$FOLLOW_REDIRECTS" = true ]; then
        CURL_OPTS+=("-L")
    fi

    if [ -n "$PROXY_URL" ]; then
        CURL_OPTS+=(--proxy "$PROXY_URL")
    fi

    # Header Kustom Biasa
    for header in "${CUSTOM_HEADERS[@]}"; do
        CURL_OPTS+=("--header" "$header")
    done

    # Header Fuzzing Payload
    if [ -n "$custom_header_key" ]; then
        CURL_OPTS+=("--header" "${custom_header_key}: ${custom_header_value}")
    fi

    # Body Data
    if [[ "$CUSTOM_METHOD" =~ ^(POST|PUT|PATCH)$ ]] && [ -n "$CUSTOM_DATA" ]; then
        CURL_OPTS+=("-d" "$CUSTOM_DATA")
    fi
    
    response=$(curl "${CURL_OPTS[@]}" "$url" 2>/dev/null)
    curl_exit_code=$?
    
    # Parsing output curl
    status_code=$(echo "$response" | awk '{print $1}')
    size=$(echo "$response" | awk '{print $2}')
    time=$(echo "$response" | awk '{print $3}')
    
    # 1. Penanganan Error Curl
    if [ $curl_exit_code -ne 0 ]; then
        LOG_MSG="${RED}[FAIL]${NC} ${log_prefix} ${url} | Code: ERROR (${curl_exit_code}) | Time: ${time}s"
        echo -e "$LOG_MSG"
        echo "$(date) ${log_prefix} [ERROR:${curl_exit_code}] ${url}" >> "$LOG_FILE"
        rm -f "$response_header_file" "$response_body_file"
        return 1
    fi

    VULN_ALERT=false

    # 2. Deteksi Anomali Cerdas (Hanya dalam Mode Fuzzing)
    if [ "$FUZZ_MODE" = true ] && [ -n "$custom_header_key" ]; then
        BASELINE=$(get_baseline "$url")
        if [ -n "$BASELINE" ]; then
            BASELINE_SIZE=$(echo "$BASELINE" | awk '{print $1}')
            BASELINE_TIME=$(echo "$BASELINE" | awk '{print $2}')
            
            # Size Delta Check (Memerlukan perhitungan absolut)
            SIZE_DIFF_RAW=$(echo "$size - $BASELINE_SIZE" | bc -l)
            SIZE_DIFF=$(echo "$SIZE_DIFF_RAW" | tr -d '-') # Nilai Absolut
            
            # Time-Based Check (Memerlukan 'bc' untuk floating point math)
            TIME_SLOW=$(echo "$time > ($BASELINE_TIME * $TIME_DELTA_FACTOR)" | bc -l)
            
            if [ $(echo "$SIZE_DIFF > $SIZE_DELTA_THRESHOLD" | bc -l) -eq 1 ]; then 
                LOG_MSG="${PURPLE}[ SIZE DELTA ]${NC} ${log_prefix} ${url} | Code: ${status_code} | ${YELLOW}CHANGE: ${SIZE_DIFF} bytes!${NC}"
                echo -e "$LOG_MSG" | tee -a "$RESULT_VULN"
                echo "$(date) ${log_prefix} [SIZE_DELTA] Change: ${SIZE_DIFF} on ${url}" >> "$LOG_FILE"
                VULN_ALERT=true
            fi
            
            if [ "$TIME_SLOW" -eq 1 ]; then 
                LOG_MSG="${PURPLE}[ TIME DELAY ]${NC} ${log_prefix} ${url} | Code: ${status_code} | ${RED}DELAY: ${time}s (>${TIME_DELTA_FACTOR}x Base)!${NC}"
                echo -e "$LOG_MSG" | tee -a "$RESULT_VULN"
                echo "$(date) ${log_prefix} [TIME_DELAY] Delay: ${time}s on ${url}" >> "$LOG_FILE"
                VULN_ALERT=true
            fi
        fi
    fi

    # 3. Deteksi Grep/String Match
    if [ -n "$GREP_STRING" ] && grep -q "$GREP_STRING" "$response_body_file"; then
        LOG_MSG="${PURPLE}[ GREP VULN ]${NC} ${log_prefix} ${url} | Code: ${status_code} | Size: ${size} | Time: ${time}s | ${RED}GREP MATCH!${NC}"
        echo -e "$LOG_MSG" | tee -a "$RESULT_VULN"
        echo "$(date) ${log_prefix} [VULN:${status_code}] Grep Match: '${GREP_STRING}' on ${url}" >> "$LOG_FILE"
        VULN_ALERT=true
    fi
    
    # 4. Logging ke Konsol (kecuali VULN ALERT sudah dicetak)
    if [ "$VULN_ALERT" = true ]; then
        : # Alert sudah dicetak di atas
    elif [ "$status_code" == "200" ]; then
        LOG_MSG="${GREEN}[ 200 OK ]${NC} ${log_prefix} ${url} | Size: ${size} | Time: ${time}s"
        echo -e "$LOG_MSG"
        echo "${log_prefix} ${url} | Size: ${size} | Time: ${time}s" >> "$RESULT_200"
    elif [[ "$status_code" =~ ^3..$ ]]; then    
        LOG_MSG="${YELLOW}[ 3XX ]${NC} ${log_prefix} ${url} | Code: ${status_code} | Time: ${time}s"
        echo -e "$LOG_MSG"
    elif [[ "$status_code" =~ ^[45]..$ ]]; then    
        LOG_MSG="${RED}[ ERR ]${NC} ${log_prefix} ${url} | Code: ${status_code} | Time: ${time}s"
        echo -e "$LOG_MSG"
    elif [ "$SILENT_MODE" = false ]; then
        LOG_MSG="${CYAN}[ CODE:${status_code} ]${NC} ${log_prefix} ${url} | Size: ${size} | Time: ${time}s"
        echo -e "$LOG_MSG"
    fi

    if [ "$SILENT_MODE" = false ] || [ "$VULN_ALERT" = true ] || [ "$status_code" != "" ]; then
        echo "$(date) ${log_prefix} [${status_code}] ${url}" >> "$LOG_FILE"
    fi
}

# --- Fungsi Multithreading dan Fuzzing ---

scan_list_multi() {
    local file="$1"

    if [ -z "$file" ] || [ ! -f "$file" ]; then
        echo -e "${RED}[!] File list URL '$file' tidak ditemukan atau nama file kosong!${NC}"
        return
    fi
    
    if [ "$FUZZ_MODE" = true ]; then
        if [ -z "$FUZZ_PAYLOAD_FILE" ] || [ ! -f "$FUZZ_PAYLOAD_FILE" ]; then
            echo -e "${RED}[!] Mode Fuzzing ON, tapi File Payload ('$FUZZ_PAYLOAD_FILE') tidak ditemukan!${NC}"
            return
        fi

        # 1. PRE-SCAN UNTUK MENGAMBIL BASELINE
        echo -e "${CYAN}--- Memulai Pre-Scan Baseline (${THREAD_COUNT} Threads) ---${NC}"
        > "$BASELINE_CACHE_FILE"
        
        # Fungsi kecil untuk pre-scan
        export -f get_baseline
        export BASELINE_CACHE_FILE
        
        cat "$file" | xargs -I {} -P "$THREAD_COUNT" bash -c '
            url=$1
            if [[ ! "$url" =~ ^https?:// ]]; then
                url="http://$url"
            fi
            # Minimal options for speed
            response=$(curl -s -k -m 10 -A "BugHunterBaseScan" -w "%{size_download} %{time_total}\n" -o /dev/null "$url" 2>/dev/null)
            
            size=$(echo "$response" | awk "{print \$1}")
            time=$(echo "$response" | awk "{print \$2}")
            url_key=$(echo "$url" | md5sum 2>/dev/null | awk "{print \$1}")
            
            if [ -n "$size" ] && [ -n "$time" ]; then
                # Menggunakan flock untuk memastikan penulisan ke file cache aman di multithread
                (
                    flock -x 200
                    echo "$url_key $size $time" >> "$BASELINE_CACHE_FILE"
                ) 200> /tmp/bh_baseline.lock
            fi
        ' _ {}
        
        echo -e "${GREEN}--- Pre-Scan Selesai. Cache Baseline Terisi (${BASELINE_CACHE_FILE}). ---${NC}"

        # 2. MEMULAI FUZZING
        echo -e "${YELLOW}--- Memulai Advanced Header Fuzzing (${THREAD_COUNT} Threads) ---${NC}"
        echo -e "${CYAN}Header: $FUZZ_HEADER_NAME | Payload File: $FUZZ_PAYLOAD_FILE | Baseline Cache: AKTIF${NC}"

        local url_list
        url_list=$(cat "$file")
        local payload_list
        payload_list=$(cat "$FUZZ_PAYLOAD_FILE")
        
        # Ekspor variabel dan fungsi penting untuk subshell
        export -f scan_single get_baseline
        export BASELINE_CACHE_FILE RESULT_DIR RESULT_200 RESULT_VULN LOG_FILE DEFAULT_USER_AGENT THREAD_COUNT PROXY_URL CURL_TIMEOUT FOLLOW_REDIRECTS SILENT_MODE SIZE_DELTA_THRESHOLD TIME_DELTA_FACTOR CUSTOM_METHOD CUSTOM_DATA CUSTOM_HEADERS FUZZ_MODE FUZZ_PAYLOAD_FILE FUZZ_HEADER_NAME GREP_STRING 
        export RED GREEN YELLOW BLUE PURPLE CYAN WHITE NC

        local combined_list=""
        for url in $url_list; do
            for payload in $payload_list; do
                combined_list+="$url|||$FUZZ_HEADER_NAME|||$payload\n"
            done
        done
        
        echo -e "$combined_list" | xargs -0 -I {} -P "$THREAD_COUNT" bash -c '
            IFS=||| read -r url header_key header_value <<< "$1"
            scan_single "$url" "$header_key" "$header_value"
        ' _ {}
        
    else
        echo -e "${YELLOW}--- Memulai Scan Multithreaded (${THREAD_COUNT} Threads) dari $file ---${NC}"
        # Ekspor fungsi dan variabel untuk subshell
        export -f scan_single get_baseline
        export RESULT_DIR RESULT_200 RESULT_VULN LOG_FILE DEFAULT_USER_AGENT THREAD_COUNT PROXY_URL CURL_TIMEOUT FOLLOW_REDIRECTS SILENT_MODE SIZE_DELTA_THRESHOLD TIME_DELTA_FACTOR CUSTOM_METHOD CUSTOM_DATA CUSTOM_HEADERS FUZZ_MODE FUZZ_PAYLOAD_FILE FUZZ_HEADER_NAME GREP_STRING
        export RED GREEN YELLOW BLUE PURPLE CYAN WHITE NC

        cat "$file" | xargs -I {} -P "$THREAD_COUNT" bash -c 'scan_single "$@"' _ {} "" ""
    fi
    
    echo -e "${YELLOW}--- Scan Selesai ---${NC}"
    echo -e "${BLUE}Lihat ${RESULT_200} untuk 200 OK, ${RESULT_VULN} untuk VULN ALERT, dan ${LOG_FILE} untuk log penuh.${NC}"
}

# --- Fungsi Menu Konfigurasi (Termasuk State Management) ---

fuzzing_config() {
    # ... (Isi fungsi ini tetap sama, namun dipanggil lagi setelah konfigurasi)
    # Gunakan fungsi ini untuk mengatur FUZZ_MODE, FUZZ_HEADER_NAME, dan FUZZ_PAYLOAD_FILE
    # ... (Tambahkan opsi "D. Kembali dan Simpan Config")
    
    echo -e "\n${BLUE}========== KONFIGURASI FUZZING (HEADER) ==========${NC}"
    echo "  A. Status Fuzzing Mode: $( [ "$FUZZ_MODE" = true ] && echo -e "${GREEN}ACTIVE${NC}" || echo -e "${RED}INACTIVE${NC}" )"
    echo "  B. Header Target: ${FUZZ_HEADER_NAME:-NONE}"
    echo "  C. File List Payload: ${FUZZ_PAYLOAD_FILE:-NONE}"
    echo "  D. Kembali ke Konfigurasi Lanjutan"
    echo -e "${BLUE}==================================================${NC}"
    
    read -p "$(echo -e "${CYAN}Pilih opsi [A-D]: ${NC}")" fuzz_choice
    
    case ${fuzz_choice,,} in
        a)
            if [ "$FUZZ_MODE" = true ]; then
                FUZZ_MODE=false
                echo -e "${RED}Fuzzing Mode dinonaktifkan.${NC}"
            else
                FUZZ_MODE=true
                echo -e "${GREEN}Fuzzing Mode diaktifkan. Harap set Header Target dan Payload File.${NC}"
            fi
            ;;
        b)
            read -p "$(echo -e "${WHITE}Masukkan Header Target (cth: X-Forwarded-For): ${NC}")" new_header_name
            FUZZ_HEADER_NAME="$new_header_name"
            echo -e "${GREEN}Header Target diatur ke: $FUZZ_HEADER_NAME${NC}"
            ;;
        c)
            read -p "$(echo -e "${WHITE}Masukkan path File List Payload: ${NC}")" new_payload_file
            if [ -f "$new_payload_file" ]; then
                FUZZ_PAYLOAD_FILE="$new_payload_file"
                echo -e "${GREEN}File Payload diatur ke: $FUZZ_PAYLOAD_FILE${NC}"
            else
                echo -e "${RED}File tidak ditemukan. Payload File tetap ${FUZZ_PAYLOAD_FILE:-NONE}.${NC}"
            fi
            ;;
        d)
            return 0
            ;;
        *)
            echo -e "${RED}Pilihan tidak valid!${NC}"
            ;;
    esac
    fuzzing_config
}

config_menu() {
    while true; do
        echo -e "\n${BLUE}========== KONFIGURASI LANJUTAN (v5.0) ==========${NC}"
        echo -e "${GREEN}[+] Current Configuration:${NC}"
        echo "  A. Threads (P-Factor): ${THREAD_COUNT}"
        echo "  B. Proxy (HTTP/SOCKS): ${PROXY_URL:-NONE}"
        echo "  C. Timeout Request (Detik): ${CURL_TIMEOUT}"
        echo "  D. Follow Redirects (-L): $( [ "$FOLLOW_REDIRECTS" = true ] && echo -e "${GREEN}ON${NC}" || echo -e "${RED}OFF${NC}" )"
        echo -e "${YELLOW}--- Deteksi Anomali ---${NC}"
        echo "  E. Grep String (Deteksi VULN): ${GREP_STRING:-NONE}"
        echo "  F. Size Delta Threshold (Bytes): ${SIZE_DELTA_THRESHOLD} (VULN jika abs(size_fuzz - size_base) > ini)"
        echo "  G. Time Delta Factor: ${TIME_DELTA_FACTOR}x (VULN jika time_fuzz > base_time * ini)"
        echo -e "${YELLOW}--- Pengujian Payload & Header ---${NC}"
        echo "  H. HTTP Method: ${CUSTOM_METHOD}"
        echo "  I. Data Body Kustom (POST/PUT): ${CUSTOM_DATA:-NONE}"
        echo "  J. Header Kustom Lain: ${#CUSTOM_HEADERS[@]} Header Aktif"
        echo "  K. Konfigurasi Fuzzing Header (Mode Baru)"
        echo -e "${PURPLE}--- State & Utility ---${NC}"
        echo "  L. User-Agent: ${DEFAULT_USER_AGENT}"
        echo "  M. Silent Log Mode: $( [ "$SILENT_MODE" = true ] && echo -e "${GREEN}ON${NC}" || echo -e "${RED}OFF${NC}" )"
        echo "  N. Simpan Konfigurasi ke $CONFIG_FILE"
        echo "  O. Kembali ke Menu Utama"
        echo -e "${BLUE}=================================================${NC}"
        
        read -p "$(echo -e "${CYAN}Pilih opsi [A-O]: ${NC}")" config_choice
        
        case ${config_choice,,} in
            a)
                read -p "$(echo -e "${WHITE}Masukkan jumlah Threads baru (default $THREAD_COUNT): ${NC}")" new_threads
                if [[ "$new_threads" =~ ^[1-9][0-9]*$ ]]; then
                    THREAD_COUNT=$new_threads
                    echo -e "${GREEN}Threads diatur ke: $THREAD_COUNT${NC}"
                else
                    echo -e "${RED}Input tidak valid. Tetap $THREAD_COUNT.${NC}"
                fi
                ;;
            b)
                read -p "$(echo -e "${WHITE}Masukkan Proxy URL (cth: http://127.0.0.1:8080) [Kosongkan untuk menghapus]: ${NC}")" new_proxy
                PROXY_URL="$new_proxy"
                if [ -n "$PROXY_URL" ]; then
                    echo -e "${GREEN}Proxy diaktifkan: $PROXY_URL${NC}"
                else
                    echo -e "${YELLOW}Proxy dinonaktifkan.${NC}"
                fi
                ;;
            c)
                read -p "$(echo -e "${WHITE}Masukkan Timeout baru (detik): ${NC}")" new_timeout
                if [[ "$new_timeout" =~ ^[1-9][0-9]*$ ]]; then
                    CURL_TIMEOUT=$new_timeout
                    echo -e "${GREEN}Timeout diatur ke: ${CURL_TIMEOUT}s${NC}"
                else
                    echo -e "${RED}Input tidak valid. Tetap ${CURL_TIMEOUT}s.${NC}"
                fi
                ;;
            d)
                FOLLOW_REDIRECTS=!$FOLLOW_REDIRECTS
                if [ "$FOLLOW_REDIRECTS" = true ]; then
                    echo -e "${GREEN}Follow Redirects diaktifkan (-L).${NC}"
                else
                    echo -e "${RED}Follow Redirects dinonaktifkan.${NC}"
                fi
                ;;
            e)
                read -p "$(echo -e "${WHITE}Masukkan String/Regex untuk Grep dalam Body (cth: 'Internal Error', atau 'X-Debug-Header'): ${NC}")" new_grep
                GREP_STRING="$new_grep"
                if [ -n "$GREP_STRING" ]; then
                    echo -e "${GREEN}Grep String diaktifkan: $GREP_STRING${NC}"
                else
                    echo -e "${YELLOW}Grep String dinonaktifkan.${NC}"
                fi
                ;;
            f)
                read -p "$(echo -e "${WHITE}Masukkan Size Delta Threshold (Bytes, default 150): ${NC}")" new_delta
                if [[ "$new_delta" =~ ^[0-9]+$ ]]; then
                    SIZE_DELTA_THRESHOLD=$new_delta
                    echo -e "${GREEN}Size Delta Threshold diatur ke: $SIZE_DELTA_THRESHOLD bytes${NC}"
                else
                    echo -e "${RED}Input tidak valid. Tetap $SIZE_DELTA_THRESHOLD.${NC}"
                fi
                ;;
            g)
                read -p "$(echo -e "${WHITE}Masukkan Time Delta Factor (misalnya 5 untuk 5x, default $TIME_DELTA_FACTOR): ${NC}")" new_factor
                # Perlu dicek apakah ini angka (integer atau float sederhana)
                if [[ "$new_factor" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
                    TIME_DELTA_FACTOR=$new_factor
                    echo -e "${GREEN}Time Delta Factor diatur ke: ${TIME_DELTA_FACTOR}x${NC}"
                else
                    echo -e "${RED}Input tidak valid. Tetap ${TIME_DELTA_FACTOR}x.${NC}"
                fi
                ;;
            h)
                read -p "$(echo -e "${WHITE}Masukkan HTTP Method baru (GET, POST, CONNECT, HEAD, dll): ${NC}")" new_method
                new_method=$(echo "$new_method" | tr '[:lower:]' '[:upper:]')
                if [ -n "$new_method" ]; then
                    CUSTOM_METHOD="$new_method"
                    echo -e "${GREEN}HTTP Method diatur ke: $CUSTOM_METHOD${NC}"
                else
                    echo -e "${RED}Metode tidak boleh kosong!${NC}"
                fi
                ;;
            i)
                read -p "$(echo -e "${WHITE}Masukkan Data Body Kustom (untuk POST/PUT): ${NC}")" new_data
                CUSTOM_DATA="$new_data"
                if [ -n "$CUSTOM_DATA" ]; then
                    echo -e "${GREEN}Data Body diatur: $CUSTOM_DATA${NC}"
                else
                    echo -e "${YELLOW}Data Body dihapus.${NC}"
                fi
                ;;
            j)
                echo -e "${PURPLE}--- Header Kustom Aktif ---${NC}"
                if [ ${#CUSTOM_HEADERS[@]} -eq 0 ]; then
                    echo -e "${YELLOW}Tidak ada header kustom aktif.${NC}"
                else
                    for i in "${!CUSTOM_HEADERS[@]}"; do
                        echo -e "$((i+1)). ${CUSTOM_HEADERS[$i]}"
                    done
                fi
                
                read -p "$(echo -e "${WHITE}Tambah Header (cth: Header: Value) [Ketik 'del' untuk menghapus semua]: ${NC}")" new_header
                if [ "$new_header" == "del" ]; then
                    CUSTOM_HEADERS=()
                    echo -e "${YELLOW}Semua Header Kustom dihapus.${NC}"
                elif [ -n "$new_header" ]; then
                    if [[ "$new_header" =~ .*:.* ]]; then
                        CUSTOM_HEADERS+=("$new_header")
                        echo -e "${GREEN}Header ditambahkan: $new_header${NC}"
                    else
                        echo -e "${RED}Format header tidak valid. Harus 'Header: Value'.${NC}"
                    fi
                fi
                ;;
            k)
                fuzzing_config # Masuk ke sub-menu fuzzing
                ;;
            l)
                read -p "$(echo -e "${WHITE}Masukkan User-Agent kustom baru: ${NC}")" new_ua
                if [ -n "$new_ua" ]; then
                    DEFAULT_USER_AGENT="$new_ua"
                    echo -e "${GREEN}User-Agent diatur ke: $new_ua${NC}"
                else
                    echo -e "${RED}User-Agent tidak boleh kosong!${NC}"
                fi
                ;;
            m)
                SILENT_MODE=!$SILENT_MODE
                if [ "$SILENT_MODE" = true ]; then
                    echo -e "${GREEN}Silent Log Mode diaktifkan.${NC}"
                else
                    echo -e "${YELLOW}Silent Log Mode dinonaktifkan.${NC}"
                fi
                ;;
            n)
                save_config
                ;;
            o)
                return 0
                ;;
            *)
                echo -e "${RED}Pilihan tidak valid!${NC}"
                ;;
        esac
    done
}

# --- Fungsi Menu Utama ---

main_menu() {
    while true; do
        echo -e "\n${BLUE}===================== MENU UTAMA (v5.0) =====================${NC}"
        echo -e "${GREEN}[+] Pilihan Aksi Bug Hunter:${NC}"
        echo "1. Scan **Single URL** (Menggunakan Payload Kustom)"
        echo "2. Scan dari **List URL** (Multithreaded)"
        echo "3. Scan dari **List URL** dengan **Advanced Fuzzing** (Base Caching Aktif)"
        echo "4. **Konfigurasi** Lanjutan & Anomali (Simpan/Muat State)"
        echo "5. Lihat **Hasil & Log**"
        echo "6. **Keluar**"
        echo -e "${BLUE}=====================================================${NC}"
        
        read -p "$(echo -e "${CYAN}Pilih [1-6]: ${NC}")" choice
        
        case $choice in
            1)
                read -p "$(echo -e "${WHITE}Masukkan URL (cth: https://target.com/ atau IP:Port): ${NC}")" url
                if [ -n "$url" ]; then
                    scan_single "$url" "" ""
                else
                    echo -e "${RED}URL tidak boleh kosong!${NC}"
                fi
                ;;
            2)
                FUZZ_MODE=false
                read -p "$(echo -e "${WHITE}Masukkan nama file list URL: ${NC}")" file_list
                scan_list_multi "$file_list"
                ;;
            3)
                FUZZ_MODE=true
                read -p "$(echo -e "${WHITE}Masukkan nama file list URL TARGET: ${NC}")" file_list
                if [ -z "$FUZZ_HEADER_NAME" ] || [ -z "$FUZZ_PAYLOAD_FILE" ]; then
                    echo -e "${RED}[!] Harap konfigurasi Header Target dan Payload File di Menu Konfigurasi (K) terlebih dahulu.${NC}"
                else
                    # Pastikan alat pendukung baseline ada (bc)
                    if command -v bc &> /dev/null; then
                        scan_list_multi "$file_list"
                    else
                        echo -e "${RED}[!] 'bc' tidak terinstall. Fungsi Anomali Cerdas (Size/Time Delta) tidak akan bekerja!${NC}"
                    fi
                fi
                ;;
            4)
                config_menu
                ;;
            5)
                echo -e "${PURPLE}--- Hasil 200 OK (${RESULT_200}) ---${NC}"
                [ -s "$RESULT_200" ] && cat "$RESULT_200" || echo -e "${YELLOW}Belum ada hasil 200 OK.${NC}"
                echo -e "${PURPLE}--- VULNERABILITY ALERTS (${RESULT_VULN}) ---${NC}"
                [ -s "$RESULT_VULN" ] && cat "$RESULT_VULN" || echo -e "${YELLOW}Belum ada VULN ALERT (Grep/Size/Time Delta).${NC}"
                echo -e "${PURPLE}--- Log Penuh (${LOG_FILE}) ---${NC}"
                echo -e "${YELLOW}Menampilkan 10 baris terakhir dari Log Penuh:${NC}"
                [ -s "$LOG_FILE" ] && tail -n 10 "$LOG_FILE" || echo -e "${YELLOW}Log Penuh kosong.${NC}"
                echo -e "${CYAN}Respons Header & Body disimpan di ${RESULT_DIR}/full_responses/*${NC}"
                ;;
            6)
                echo -e "${RED}Keluar dari Bug Hunter Tool... Sampai jumpa!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Pilihan tidak valid! Masukkan angka antara 1 sampai 6.${NC}"
                ;;
        esac
    done
}


show_banner
load_config         
check_dependencies
main_menu
