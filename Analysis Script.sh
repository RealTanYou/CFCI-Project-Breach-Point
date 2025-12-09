#!/bin/bash

# Student Name: Tan You
# Student Code: s29
# Class Code: CCK2_250506
# Lecturer's Name: Tushar

set +H

declare __helpMenu="
Required dependencies:
Bulk Extractor
Binwalk
Foremost
Volatility

Usage: $0 [OPTIONS]

Options:
    -h                          Displays this help menu and exit
    -c [a OR c]                 Choice to choose either Memory Analysis (a) or File Carving (c)
                                Note that File Carving requires super user permissions
    -f [NAME OF FILE]           Fully qualified path to the file to be analysed or carved. 
    -d [DIR_NAME]               Optional argument. Fully qualified name of output directory that
                                all output files and report will be saved into.
                                If no name is give, a default name of the file name and current datetime will be used.
                                And the directory will be created where this program is ran.

Example:

$0 -c a -f /home/user/documents/file_to_be_analysed.txt
sudo $0 -c c -f /home/user/documents/file_to_be_carved.mem -d /home/user/documents/output_dir
"

if [ $# -eq 0 ]; then
    echo "No options given. Use the '-h' options to see the help menu."
    exit 0
fi
declare starttime
declare endtime
declare time_diff
declare total_files_created
declare current_analysis_file_name=$0
declare breakpoint="--------------------"
declare all_argument_pass=true #true = all arguments pass the test, false = at least one failed
declare current_datetime=$(date +"%Y-%m-%d_%H-%M-%S")
declare choice
declare dir_name
declare report_file_name="report.log"
declare given_file
declare carved_tools_used="bulk_extractor, foremost, binwalk and strings"
declare -a tools_to_check=("bulk_extractor" "foremost" "binwalk" "strings")
declare -A commands_to_install=(["bulk extractor"]="bulk-extractor"
["foremost"]="foremost"
["binwalk"]="binwalk")
declare bulk_extractor_dir="bulk_extractor_output"
declare foremost_dir="foremost_output"
declare binwalk_dir="binwalk_output"
declare strings_file="strings.txt"
declare mem_profile_vol2_file="mem_profile_vol2.txt"
declare proc_info_file="proc_info.txt"
declare network_connection_file="network_connections.txt"
declare commands_executed_file="commands_executed.txt"
declare dll_list_file="dll_list.txt"
declare hashes_file="hashes.txt"
declare registry_info_file="registry_info.txt"
declare sid_list_file="sid_list.txt"

log_output(){
    # For anything important done in this script, append them into the log file.
    # Formatted appropriately for easy reading.
    info=$1
    log_input="$(date -u '+%a %F %T:%N %Z')"": "$info
    echo $log_input >> $dir_name/$report_file_name
}

check_installed() {
    # given the name of the tool, check if it is installed.
    # if not, then install it.
    tool=$1
    log_output "checking if $tool is installed."
    is_it_installed="$(command -v $tool)"
    if [ -z "$is_it_installed" ]; then
        echo "[#]" $tool "is not installed. installing..."
        sudo apt-get -qq install ${commands_to_install[$tool]} > /dev/null
        echo "[#]" $tool "is now installed."
        log_output "$tool is now installed."
    else
        echo "[#]" $tool "is already installed."
        log_output "$tool is already installed."
    fi
    echo $breakpoint 
}

memory_analysis(){
    #run memory analysis
    #ask the user to run Volatility 2 or 3. Also as the user to pass in the name of the command for Volatility 2 or 3.
    echo "For memory analysis, please ensure that your system has at least Volatility 2 or 3 installed."
    echo "Please make sure that you are currently in the correct virtual environment to run either."
    input_correct=false
    volatilitychoice=2
    volatilitycommand="vol.py"
    while [[ "$input_correct" == false ]] do
        read -p "Press Enter to use Volatility 2, otherwise enter 3 to Volatility 3: " volatilitychoice
            if [[ -z $volatilitychoice ]]; then
                volatilitychoice=2
                input_correct=true
            elif [[ $volatilitychoice != 2 && $volatilitychoice != 3 ]]; then
                echo "Volatility choice should be either 2 for Volatility 2, or 3 for Volatility 3."
                input_correct=false
            else
                input_correct=true
            fi
    done
    input_correct=false
    while [[ "$input_correct" == false ]] do
        read -p "As each system calls Volatility differently, please give the name of the command used to call your choice of Volatility: " volatilitycommand
            if [[ -z $volatilitycommand ]]; then
                echo "Error: Given input is empty."
                input_correct=false
            else
                input_correct=true
            fi
    done
    echo "checking if the file can be analyzed with the given version of volatility..."
    case $volatilitychoice in
        2)
            checkvol=$(vol.py -f $given_file imageinfo)
            if [[ "$checkvol" =~ "Image date and time" ]]; then
                echo "File given appears to work with volatility 2."
            else
                echo "File given does not appear to work with volatility 2. Please check your file."
                exit
            fi
            ;;
        3)
            checkvol=$($volatilitycommand -f $given_file windows.info)
            if [[ $checkvol =~ "Unsatisfied requirement" ]]; then
                echo "File given does not appear to work with volatility 3. Please check your file."
                exit
            else
                echo "File given appears to work with volatility 3."
            fi
            ;;
        \?)
            echo "Unknown error occured. Could be due to given command or file."
            exit
            ;;
    esac
    echo $breakpoint
    echo "Analyzing file..."
    starttime=$(date +%s)
    case $volatilitychoice in
        2)
            echo "Getting memory profile"
            $volatilitycommand -f $given_file imageinfo > $dir_name/$mem_profile_vol2_file
            vol2_meminfo=$(cat $dir_name/$mem_profile_vol2_file| grep "Suggested Profile(s)" | awk -F' : ' '{print $2}' | awk -F, '{print $1}')
            echo $breakpoint
            echo "Getting processes"
            $volatilitycommand -f $given_file --profile=$vol2_meminfo pslist > $dir_name/$proc_info_file
            echo "Found running processes for your file:"
            cat $dir_name/$proc_info_file
            echo $breakpoint
            $volatilitycommand -f $given_file --profile=$vol2_meminfo pstree >> $dir_name/$proc_info_file
            $volatilitycommand -f $given_file --profile=$vol2_meminfo psscan >> $dir_name/$proc_info_file
            log_output "Process list from $given_file has been extracted and saved at $dir_name/$proc_info_file."
            echo $breakpoint
            echo "Getting network connections"
            $volatilitycommand -f $given_file --profile=$vol2_meminfo connscan > $dir_name/$network_connection_file
            $volatilitycommand -f $given_file --profile=$vol2_meminfo sockets >> $dir_name/$network_connection_file
            echo "Found network connections for your file:"
            cat $dir_name/$network_connection_file
            echo $breakpoint
            log_output "Network connections from $given_file has been extracted and saved at $dir_name/$network_connection_file."
            echo $breakpoint
            echo "Getting executed commands"
            $volatilitycommand -f $given_file --profile=$vol2_meminfo consoles > $dir_name/$commands_executed_file
            $volatilitycommand -f $given_file --profile=$vol2_meminfo cmdline >> $dir_name/$commands_executed_file
            echo "Found commands executed for your file:"
            cat $dir_name/$commands_executed_file
            echo $breakpoint
            log_output "Commands executed from $given_file has been extracted and saved at $dir_name/$commands_executed_file."
            echo $breakpoint
            echo "Getting DLL lists"
            $volatilitycommand -f $given_file --profile=$vol2_meminfo dlllist > $dir_name/$dll_list_file
            log_output "DLL list from $given_file has been extracted and saved at $dir_name/$dll_list_file."
            echo $breakpoint
            echo "Getting registry information"
            $volatilitycommand -f $given_file --profile=$vol2_meminfo hivelist > $dir_name/$registry_info_file
            log_output "Registry list from $given_file has been extracted and saved at $dir_name/$registry_info_file."
            echo $breakpoint
            echo "Getting password hashes"
            system_hive_addr=$(cat $dir_name/$registry_info_file | grep -i "system" | awk '{print $1}')
            sam_hive_addr=$(cat $dir_name/$registry_info_file | grep -i "sam" | awk '{print $1}')
            $volatilitycommand -f $given_file --profile=$vol2_meminfo hashdump -y $system_hive_addr -s $sam_hive_addr > $dir_name/$hashes_file
            echo "Found hashes for your file:"
            cat $dir_name/$hashes_file
            echo $breakpoint
            log_output "Password Hashes from $given_file has been extracted and saved at $dir_name/$hashes_file."
            echo $breakpoint
            echo "Getting SID list"
            $volatilitycommand -f $given_file --profile=$vol2_meminfo getsids > $dir_name/$sid_list_file
            log_output "SID list from $given_file has been extracted and saved at $dir_name/$sid_list_file."
            log_output "Given file $given_file has been analyzed with Volatility 2. Information saved at $dir_name"
            echo "Given file $given_file has been analyzed with Volatility 2. Information saved at $dir_name"
            ;;
        3)
            echo "Getting processes"
            $volatilitycommand -f $given_file -r pretty windows.pslist.PsList > $dir_name/$proc_info_file
            echo "Found running processes for your file:"
            cat $dir_name/$proc_info_file
            echo $breakpoint
            log_output "Process list from $given_file has been extracted and saved at $dir_name/$proc_info_file."
            echo "Getting network connections"
            $volatilitycommand -f $given_file windows.netscan.NetScan > $dir_name/$network_connection_file
            echo "Found network connections for your file:"
            cat $dir_name/$network_connection_file
            echo $breakpoint
            log_output "Network connections from $given_file has been extracted and saved at $dir_name/$network_connection_file."
            echo "Getting executed commands"
            $volatilitycommand -f $given_file windows.cmdline.CmdLine > $dir_name/$commands_executed_file
            echo "Found commands executed for your file:"
            cat $dir_name/$commands_executed_file
            echo $breakpoint
            log_output "Commands executed from $given_file has been extracted and saved at $dir_name/$commands_executed_file."
            echo "Getting DLL list"
            $volatilitycommand -f $given_file windows.dlllist.DllList > $dir_name/$dll_list_file
            log_output "DLL list from $given_file has been extracted and saved at $dir_name/$dll_list_file."
            echo $breakpoint
            echo "Getting Registry list"
            $volatilitycommand -f $given_file windows.registry.hivelist.HiveList > $dir_name/$registry_info_file
            log_output "Registry list from $given_file has been extracted and saved at $dir_name/$registry_info_file."
            echo $breakpoint
            echo "Getting password hashes"
            $volatilitycommand -f $given_file windows.registry.hashdump.Hashdump > $dir_name/$hashes_file
            echo "Found hashes for your file:"
            cat $dir_name/$hashes_file
            echo $breakpoint
            log_output "Password Hashes from $given_file has been extracted and saved at $dir_name/$hashes_file."
            echo "Getting SID list"
            $volatilitycommand -f $given_file windows.getservicesids.GetServiceSIDs > $dir_name/$sid_list_file
            log_output "SID list from $given_file has been extracted and saved at $dir_name/$sid_list_file."
            log_output "Given file $given_file has been analyzed with Volatility 3. Information saved at $dir_name"
            echo "Given file $given_file has been analyzed with Volatility 3. Information saved at $dir_name"
            ;;
        \?)
            echo "Unknown error occured. Could be due to given command or file."
            exit
            ;;
    esac
}

file_carving(){
    #run file carving
    #use bulk extractor, foremost and binwalk to carve the file
    echo "Carving $given_file..."
    starttime=$(date +%s)
    echo "Using bulk extractor"
    bulk_extractor --no_notify $given_file -o $dir_name/$bulk_extractor_dir
    echo $breakpoint
    echo "Using foremost"
    foremost -i $given_file -o $dir_name/$foremost_dir
    echo $breakpoint
    echo "Using binwalk"
    binwalk --run-as=root --exclude="gzip" --exclude="zlib" --exclude="lzma" --exclude="lzo" --exclude="bzip2" --exclude="zip" --exclude="tar" --exclude="7z" --exclude="7zip" -e $given_file -C $dir_name/$binwalk_dir
    echo $breakpoint
    echo "Using strings"
    strings -n 5 $given_file > $dir_name/$strings_file
    echo $breakpoint
    log_output "$given_file has been carved with $carved_tools_used and saved at $dir_name/$bulk_extractor_dir, $dir_name/$foremost_dir, $dir_name/$binwalk_dir and $dir_name/$strings_file"
    echo "$given_file has been carved with $carved_tools_used and saved at $dir_name/$bulk_extractor_dir, $dir_name/$foremost_dir, $dir_name/$binwalk_dir and $dir_name/$strings_file"
    network_files=$(find $dir_name -type f -name ".pcap" -o -name ".cap" )
    echo $breakpoint
    if [[ -z $network_files ]]; then
        echo "No network traffic could be found in $given_file."
        log_output "No network traffic could be found in $given_file."
    else
        input_correct=false
        for network_file in $network_files; do
            file_size=$(du $network_file | awk '{print $1}')
            if [[ $file_size > 0 ]]; then
                input_correct=true
                echo "Found network traffic. Stored in $network_file."
                log_output "Found network traffic. Stored in $network_file."
            fi
        done
        if [[ "$input_correct" == false ]]; then
            echo "No network traffic could be found in $given_file."
            log_output "No network traffic could be found in $given_file."
        fi
    fi
    echo $breakpoint
    echo "Finding human-readable data..."
    #find all the executable files, then get their directories.
    executable_files=$(find $dir_name -type f -name "*.exe" -o -name "*.dll" | awk -F/ '{for (i=1; i<NF; i++) printf "%s/", $i, (i==NF-1 ? "" : OFS); printf "\n"}' | sort | uniq)
    if [[ -z $executable_files ]]; then
        echo "No executable files could be found in $given_file."
        log_output "No executable files could be found in $given_file."
    else
        echo "Found executable files in the following folders:"
        log_output "Found executable files in the following folders:"
        for executable_file in $executable_files; do
            echo "$executable_file"
            log_output "$executable_file"
        done
    fi
    echo $breakpoint
    email_files=$(find $dir_name -type f -name "email*")
    if [[ -z $email_files ]]; then
        echo "No emails could be found in $given_file."
        log_output "No emails could be found in $given_file."
    else
        input_correct=false
        for email_file in $email_files; do
            file_size=$(du $email_file | awk '{print $1}')
            if [[ $file_size > 0 ]]; then
                input_correct=true
                echo "$email_file has emails. Showing up to the first 10 results of the file:"
                log_output "$email_file has emails."
                tail -n +6 $email_file | head -n 10
                echo $breakpoint
            fi
        done
        if [[ "$input_correct" == false ]]; then
            echo "No emails could be found in $given_file."
            log_output "No emails could be found in $given_file."
        fi
    fi
    echo $breakpoint
    ip_files=$(find $dir_name -type f -name "ip*")
    if [[ -z $ip_files ]]; then
        echo "No ip addresses could be found in $given_file."
        log_output "No ip addresses could be found in $given_file."
    else
        input_correct=false
        for ip_file in $ip_files; do
            file_size=$(du $ip_file | awk '{print $1}')
            if [[ $file_size > 0 ]]; then
                input_correct=true
                echo "$ip_file has ip addresses. Showing up to the first 10 results of the file:"
                log_output "$ip_file has emails."
                tail -n +6 $ip_file | head -n 10
                echo $breakpoint
            fi
        done
        if [[ "$input_correct" == false ]]; then
            echo "No ip addresses could be found in $given_file."
            log_output "No ip addresses could be found in $given_file."
        fi
    fi
    echo $breakpoint
    url_files=$(find $dir_name -type f -name "url*")
    if [[ -z $url_files ]]; then
        echo "No .onion URLs could be found in $given_file."
        log_output "No .onion URLs could be found in $given_file."
    else
        input_correct=false
        for url_file in $url_files; do
            file_size=$(du $url_file | awk '{print $1}')
            if [[ $file_size > 0 ]]; then
                #check if url file has .onion links
                onion_urls=$(grep -i "*.onion" $url_file)
                if [[ ! -z $onion_urls ]]; then
                    input_correct=true
                    echo "$url_file has .onion URLs. Showing up to the first 10 results of the file:"
                    log_output "$url_file has .onion URLs."
                    echo "${onion_urls[@]:0:10}"
                    echo $breakpoint
                fi
            fi
        done
        if [[ "$input_correct" == false ]]; then
            echo "No .onion URLs could be found in $given_file."
            log_output "No .onion URLs could be found in $given_file."
        fi
    fi
    echo $breakpoint
    credentials=$(grep -iE "password=|passwd=|username=|user=" $dir_name/$strings_file)
    if [[ -z $credentials ]]; then
        echo "No credentials could be found in $given_file."
        log_output "No credentials could be found in $given_file."
    else
        echo "Found some potential credentials in $dir_name/$strings_file. Showing up to the first 10 results:"
        echo "${credentials[@]:0:10}"
        log_output "Found some potential credentials in $dir_name/$strings_file."
        echo $breakpoint
    fi
}

# Check each option for values
while getopts "c:d:f:h" option; do
    case $option in
        c) # get choice
            choice=$OPTARG;;
        d) # get directory name
            dir_name=$OPTARG;;
        f) # get given file
            given_file=$OPTARG;;
        h) # display Help menu and exit
            echo "$__helpMenu"
            exit;;
        \?) # tell user to use the help menu and exit
            echo "Unknown error or invalid option. Use the '-h' options to see the help menu"
            exit;;
   esac
done

#only get the starttime once an operation first starts, and not during installation.

echo "Running program, checking for errors in input."
# check if each input is valid and available.
if [[ -z $choice ]]; then
    echo "Choice must be given."
    all_argument_pass=false
elif [[ $choice != "a" && $choice != "c" ]]; then
    echo "Choice must be either \'a\' for Memory Analysis, or \'c\' for File Carving."
    all_argument_pass=false
fi
if [[ -z $given_file ]]; then
    echo "File must be given."
    all_argument_pass=false
elif [[ ! -f $given_file ]]; then
    echo "File does not exists."
    all_argument_pass=false
fi
if [[ -z $dir_name ]]; then
    echo "No Directory name given. File name and current date will be used as the default directory"
    dir_name="$(echo $given_file | tr '/' '_' )"+$current_datetime
    mkdir $dir_name
elif [[ ! -d $dir_name ]]; then
    echo "Directory name given does not exist."
    all_argument_pass=false
fi
if [[ "$all_argument_pass" == false ]]; then
    echo "There were errors. Use the '-h' options to see the help menu"
    exit 1
else
    echo "No errors could be found. Continuing..."
fi

touch $dir_name/$report_file_name

if [[ $choice == "a" ]]; then
    #run memory analysis
    echo "Memory Analysis was chosen."
    echo $breakpoint
    memory_analysis
    echo $breakpoint
else
    #run file carving
    echo "File carving was chosen."
    echo $breakpoint
    # This code checks if the script is being run as root. if not, exit.
    # This line is placed here after "File carving" so that it is possible to update and/or install.
    if [ "$(id -u)" -ne 0 ]; then
        echo "Root/Superuser privileges are required to run file carving. Use the '-h' option to see the help menu"
        exit
    fi
    echo "[#] Updating repositories..."
    sudo apt-get -qq update 2>/dev/null
    echo "[#] Updated repositories"
    echo "[#] Checking for installation of forensic tools..."
    echo $breakpoint 
    for tool in "${tools_to_check[@]}"
    do
        check_installed $tool
    done
    echo "Running file carving..."
    file_carving
    echo $breakpoint
fi

endtime=$(date +%s)
time_diff=$(($endtime - $starttime))
total_files_created=$(find $dir_name -type f | wc -l)
echo $breakpoint
echo "Operation completed in $time_diff seconds."
log_output "Operation completed in $time_diff seconds."
echo "Total number of files created: $total_files_created."
log_output "Total number of files created: $total_files_created."
echo "All results stored in $dir_name"
log_output "All results stored in $dir_name"
echo "Zipping extracted files and report log..."
zip -rq $dir_name.zip $dir_name
echo "Zipped file at $dir_name.zip"