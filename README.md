# Twister

Permutation engine for generating and checking the availability of malicious
Twitter usernames. Several edit operations are supported: substitution,
transposition, insertion, deletion, and prefix/suffix. Inspired by
[dnstwist](https://github.com/elceef/dnstwist "dnstwist on GitHub").


![Twister Screenshot](https://github.com/mh0x/twister/blob/master/img/twister.png
"Twister Screenshot")


## Prerequisites

 * Python 3


## Install

```
git clone https://github.com/mh0x/twister.git
```


## Usage

```
usage: twister.py [-h] [-c] [-q] [-o OUTPUT] [-n THREADS]
                  [-r RETRIES] [-t TIMEOUT] profile user [user ...]

positional arguments:
  profile                        generator profile json
  user                           target username(s)

optional arguments:
  -h, --help                     show this help message and exit
  -c, --check                    check availability of generated usernames
  -q, --quiet                    suppress messages sent to stdout
  -o OUTPUT, --output OUTPUT     output results to csv file
  -n THREADS, --threads THREADS  max concurrent requests (default: 5)
  -r RETRIES, --retries RETRIES  max request retries (default: 2)
  -t TIMEOUT, --timeout TIMEOUT  request timeout, secs (default: 10)

edit operations:                              notation:
  {"sub": {x: [y, ...], ...}, "max": n}         x, y  characters
  {"tra": [[x, y], ...], "max": n}              u     strings
  {"ins": {x: [y, ...], ...}, "max": n}         n     positive integers
  {"del": [x, ...], "max": n}
  {"pre": [u, ...]}
  {"suf": [u, ...]}
```


## Profiles

A generator profile is a JSON description of a pipeline of edit operations:

> `[` _o_<sub>1</sub> `,` _o_<sub>2</sub> `,` _o_<sub>3</sub> `,` ...
> _o_<sub>_n_</sub> `]`

The output of _o_<sub>1</sub> passed to _o_<sub>2</sub>, whose output is passed
to _o_<sub>3</sub>, and so on to _o_<sub>_n_</sub>.


### Operations

Supported edit operations are described below using the following notation:

 * ‘_x_’ and ‘_y_’ range over characters;
 * ‘_u_’ and ‘_v_’ range over strings;
 * ‘_n_’ ranges over positive integers;
 * asterisks denote Kleene star (ignoring comma separators).

**Note:** Operations that perform single-character edits have a `max` property
that specifies their maximum edit distance.


#### Substitution (_uxv_ → _uyv_)

> `{"sub":{` (`"` _x_ `":[` (`"` _y_ `"`)\* `]`)\* `},"max":` _n_ `}`


#### Transposition (_uxyv_ → _uyxv_)

> `{"tra":[` (`["` _x_ `","` _y_ `"]`)\* `],"max":` _n_ `}`


#### Insertion (_uxv_ → _uxyv_)

> `{"ins":{` (`"` _x_ `":[` (`"` _y_ `"`)\* `]`)\* `},"max":` _n_ `}`


#### Deletion (_uxv_ → _uv_)

> `{"del":[` (`"` _x_ `"`)\* `],"max":` _n_ `}`


#### Prefix (_u_ → _vu_)

> `{"pre":[` (`"` _v_ `"`)\* `]}`


#### Suffix (_u_ → _uv_)

> `{"suf":[` (`"` _v_ `"`)\* `]}`


### Examples

Some examples of individual edit operations are provided in
[ops/](https://github.com/mh0x/twister/blob/master/ops "Example Operations"):

 * [Common Deletions](https://github.com/mh0x/twister/blob/master/ops/common_deletions.json
   "ops/common_deletions.json") (taken from
   [[1](https://datagenetics.com/blog/november42012/index.html
   "Reference: Sloppy Typing")])
 * [Common Transpositions](https://github.com/mh0x/twister/blob/master/ops/common_transpositions.json
   "ops/common_transpositions.json") (taken from
   [[1](https://datagenetics.com/blog/november42012/index.html
   "Reference: Sloppy Typing")])
 * [Company Suffixes](https://github.com/mh0x/twister/blob/master/ops/company_suffixes.json
   "ops/company_suffixes.json") (taken from
   [[2](https://www.harborcompliance.com/information/company-suffixes
   "Reference: Company Suffixes")])
 * [Double Hits](https://github.com/mh0x/twister/blob/master/ops/double_hits.json
   "ops/double_hits.json")
 * [Fat Fingers](https://github.com/mh0x/twister/blob/master/ops/fat_fingers.json
   "Source: ops/fat_fingers.json")
 * [Homoglyphs](https://github.com/mh0x/twister/blob/master/ops/homoglyphs.json
   "ops/homoglyphs.json") (taken from
   [[3](https://security.stackexchange.com/a/128463
   "Reference: List of Visually Similar Characters for Detecting Spoofing and Social Engineering Attacks")])
 * [Language Code Suffixes](https://github.com/mh0x/twister/blob/master/ops/lang_code_suffixes.json
   "ops/lang_code_suffixes.json") (taken from
   [[4](https://www.loc.gov/standards/iso639-2/php/code_list.php
   "Reference: ISO 639.2: Codes for the Representation of Names of Languages")])
 * [Mishits](https://github.com/mh0x/twister/blob/master/ops/mishits.json
   "ops/mishits.json")

**Note:** `max` values are provisionally set to `1`.


### Complex Profiles

The `profile` argument accepts a JSON string or a path to a JSON file. The
latter option is useful for specifying complex profiles. Alternatively,
individual edit operations may be saved (cf.
[ops/](https://github.com/mh0x/twister/blob/master/ops "Example Operations"))
and composed on the command line:

```
twister.py [args ...] <<< echo "[$(cat op1.json), $(cat op2.json), ...]" user [user ...]
```


## Usernames

Twitter usernames are case-insensitive strings of 1–15 characters (`a`–`z`,
`A`–`Z`, `0`–`9`, `_`)
[[5](https://help.twitter.com/en/managing-your-account/twitter-username-rules
"Reference: Help with Username Registration")]. Hence, `user` and `profile`
arguments are converted to lower-case.


## Output

The `-o/--output` option outputs the results to a given file, in CSV format.
The first column contains generated usernames. If the `-c/--check` option is
specified, there is a second column that contains their availability status
(`1` available, `0` unavailable, `-1` error).


## References

 1. Sloppy Typing<br />
    [https://datagenetics.com/blog/november42012/index.html](https://datagenetics.com/blog/november42012/index.html
    "Reference: Sloppy Typing")

 2. Copmany Suffixes<br />
    [https://www.harborcompliance.com/information/company-suffixes](https://www.harborcompliance.com/information/company-suffixes
    "Reference: Company Suffixes")

 3. List of Visually Similar Characters for Detecting Spoofing and Social
    Engineering Attacks<br/>
    [https://security.stackexchange.com/a/128463](https://security.stackexchange.com/a/128463
    "Reference: List of Visually Similar Characters for Detecting Spoofing and Social Engineering Attacks")

 4. ISO 639.2: Codes for the Representation of Names of Languages<br />
    [https://www.loc.gov/standards/iso639-2/php/code_list.php](https://www.loc.gov/standards/iso639-2/php/code_list.php
    "Reference: ISO 639.2: Codes for the Representation of Names of Languages")

 5. Help with Username Registration<br />
    [https://help.twitter.com/en/managing-your-account/twitter-username-rules](https://help.twitter.com/en/managing-your-account/twitter-username-rules
    "Reference: Help with Username Registration")


## License

[MIT](https://github.com/mh0x/twister/blob/master/LICENSE "MIT License")
© 2018 mh0x


## Disclaimer

Taken from [MIT License](https://github.com/mh0x/twister/blob/master/LICENSE
"MIT License"):

> IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
> DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
> OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
> OR OTHER DEALINGS IN THE SOFTWARE.
