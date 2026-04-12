# YARIS
Small utility that helps me run &amp; manage Yara rules.

Usage examples:
```bash
# List all rules in a directory
./yaris rules ./my_yara

# Count up all rule tags in a directory 
./yaris tags list ./my_yara

# Add specific tags to all rules in a directory
./yaris tags update -t elastic ./my_yara/elastic
# Add specific tags by file name or rule name
./yaris tags update -t linux -n linux ./my_yara
./yaris tags update -t windows -f windows ./my_yara

# Run all rules
./yaris run ./my_yara ./target
# Run all rules & exclude or include tags
./yaris run -e windows ./my_yara ./target
./yaris run -i linux ./my_yara ./target
# Run all rules print offset
./yaris run -s ./my_yara ./target
# Run all rules print hex dump (optionally set amount of bytes to dump)
./yaris run -x ./my_yara ./target
./yaris run -x -l 64 ./my_yara ./target

# Export rules based on tags
# Useful if rules are used for other tools
./yaris export -t linux,webshells ./my_yara
./yaris export -t linux,webshells -o output.yara ./my_yara
```
