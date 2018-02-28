# Test suite for the HeapHopper tool

## Currently working tests

    * fastbin_dup
    * house_of_einherjar
    * house_of_lore
    * house_of_spirit
    * unsafe_unlink
    * overlapping_chunks
    * unsorted_bin_attack
    * poison_null_byte

## WIP test

    * house_of_orange

## Not doable right now

    * house_of_force (needs specific allocation sizes)

## How to run

`python run_tests.py`

    * Results will be stored in `*date*_test.txt`
