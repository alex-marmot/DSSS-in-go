package main

import (
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/urfave/cli"
	"math/rand"
	"os"
	"regexp"
	"strings"
	"github.com/anaskhan96/soup"
)

const (
	NAME             = "Damn Small SQLi Scanner (DSSS) in Golang"
	VERSION          = "0.0000000000001a"
	AUTHOR           = "Alex"
	EMAIL            = "alex-marmot@gmail.com"
	//COOKIE           = "Cookie"                                                        // optional HTTP header names
	//UA               = "User-Agent"                                                    // optional HTTP header names
	//REFERER          = "Referer"                                                       // optional HTTP header names
	//FUZZY_THRESHOLD  = 0.95                                                            // ratio value in range (0,1) used for distinguishing True from False responses
	//TIMEOUT          = 30                                                              // connection timeout in seconds
	//BLOCKED_IP_REGEX = `(?i)(\A|\b)IP\b.*\b(banned|blocked|bl(a|o)ck\s?list|firewall)` // regular expression used for recognition of generic firewall blocking messages
	//TEXT             = iota                                                            // enumerator-like values used for marking content type
	//HTTPCODE
	//TITLE
	//HTML
)

var (
	//HTTPMETHODS          = []string{"GET", "POST"}                 // HTTP methods
	//PREFIXES             = []string{" ", ") ", "' ", "') "}        // prefix values used for building testing blind payloads
	//SUFFIXES             = []string{"", "-- -", "#", "%%16"}       // suffix values used for building testing blind payloads
	//TAMPER_SQL_CHAR_POOL = []string{"(', ')", `'`, "\""}           // characters used for SQL tampering/poisoning of parameter values
	RANDINT              = rand.Intn(255)                          // random integer value used across all tests
	BOOLEAN_TESTS        = []string{" AND %d=%d", " OR NOT (%d>%d)"} // boolean tests used for building testing blind payloads
	DBMS_ERRORS          = map[string][]string{
		"MySQL":                {`SQL syntax.*MySQL`, `Warning.*mysql_.*`, `valid MySQL result`, `MySqlClient\.`},
		"PostgreSQL":           {`PostgreSQL.*ERROR`, `Warning.*\Wpg_.*`, `valid PostgreSQL result`, `Npgsql\.`},
		"Microsoft SQL Server": {`Driver.* SQL[\-\_\ ]*Server`, `OLE DB.* SQL Server`, `(\W|\A)SQL Server.*Driver`, `Warning.*mssql_.*`, `(\W|\A)SQL Server.*[0-9a-fA-F]{8}`, `(?s)Exception.*\WSystem\.Data\.SqlClient\.`, `(?s)Exception.*\WRoadhouse\.Cms\.`},
		"Microsoft Access":     {`Microsoft Access Driver`, `JET Database Engine`, `Access Database Engine`},
		"Oracle":               {`\bORA-[0-9][0-9][0-9][0-9]`, `Oracle error`, `Oracle.*Driver`, `Warning.*\Woci_.*`, `Warning.*\Wora_.*`},
		"IBM DB2":              {`CLI Driver.*DB2`, `DB2 SQL error`, `\bdb2_\w+\(`},
		"SQLite":               {`SQLite/JDBCDriver`, `SQLite.Exception`, `System.Data.SQLite.SQLiteException`, `Warning.*sqlite_.*`, `Warning.*SQLite3::`, `\[SQLITE_ERROR\]`},
		"Sybase":               {`(?i)Warning.*sybase.*`, `Sybase message`, `Sybase.*Server message.*`},
	}
)



func get(url string) string {
	resp, err := soup.Get(url)
	if err != nil {
		panic(err.Error())
	}
	return resp
}

func scan(url string) {
	matched := strings.HasSuffix(url, ".html")
	if matched {
		fmt.Printf(url + " not match URL format \n")
	}
	body := get(url + "%29%28%22%27")

	for dbName, regs := range DBMS_ERRORS {
		for _, reg := range regs {
			res, err := regexp.MatchString(reg, body)

			if err != nil {
				panic(err.Error())
			}

			if res {
				fmt.Printf("SQLInjection Found: %s \ndatabase: %s \n", url, dbName)
			}
		}
	}

	for _, payload := range BOOLEAN_TESTS {
		origin := get(url)
		testURL := url + payload
		boolEqualURL := fmt.Sprintf(testURL, RANDINT, RANDINT)
		boolEqual := get(boolEqualURL)
		boolNotEqualURL := fmt.Sprintf(testURL, RANDINT, RANDINT+1)
		boolNotEqual := get(boolNotEqualURL)
		if (origin == boolEqual) && (origin != boolNotEqual) {
			fmt.Printf("SQLInjection Found:  %s \n", url)
		}

	}

	fmt.Printf("Done!")
}

func main() {
	app := cli.NewApp()
	app.Name = NAME
	app.Version = VERSION
	app.Author = AUTHOR
	app.Email = EMAIL

	app.Usage = "./dsss [options]"
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:        "debug, d",
			Usage:       "run in debug mode",
		},
		cli.StringFlag{
			Name:        "url, u",
			Usage:       "Setting target URL",
		},
		cli.StringFlag{
			Name:        "data, D",
			Usage:       "Setting post data",
		},
		cli.StringFlag{
			Name:        "cookie",
			Usage:       "Setting cookie",
		},
		cli.StringFlag{
			Name:        "user-agent, UA",
			Usage:       "Setting user-agent",
		},
		cli.StringFlag{
			Name:        "referer",
			Usage:       "Setting referer",
		},
		cli.StringFlag{
			Name:        "proxy",
			Usage:       "Setting HTTP headers",
		},
	}

	app.Action = func(c *cli.Context) {
		url := c.String("url")
		if len(url) == 0 {
			logrus.Errorf("Pass an url, ex: http://www.target.com/page.php?id=1")
			cli.ShowAppHelp(c)
			return
		}

		scan(url)

	}

	app.Run(os.Args)

}
