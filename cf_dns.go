package main

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/olekukonko/tablewriter"
)

type CFClient struct {
	Client     *http.Client
	Request    *http.Request
	Error      error
	Token      string
	Zones      map[string]string
	DNS        map[string]CFResponseListDNS
	MyPublicIP string
	Domain     string
}

type CFResponseResult struct {
	ID         string `json: "id"`
	Name       string `json: "name"`
	Status     string `json: "status"`
	ModifiedOn string `json: "modified_on"`
}

type CFResponse struct {
	Result []CFResponseResult
}

type CFResponseListDNS struct {
	ID         string `json: "id"`
	ZoneID     string `json: "zone_id"`
	ZoneName   string `json: "zone_name"`
	Name       string `json: "name"`
	Type       string `json: "type"`
	Proxied    bool   `json: "proxied"`
	TTL        int    `json: "ttl"`
	ModifiedOn string `json: "modified_on"`
}

type CFResponseResultListDNS struct {
	Result []CFResponseListDNS
}

type CFCreateDNSRecord struct {
	Type     string `json: "type"`
	Name     string `json: "name"`
	Content  string `json: "content"`
	TTL      int    `json: "ttl"`
	Priority int    `json: "priority"`
	Proxied  bool   `json: "proxied"`
}

func getEnvVar(key string) (string, error) {
	envVar, ok := os.LookupEnv(key)
	if !ok {
		err := fmt.Errorf("%s is not set in environment", key)

		return "", err
	}

	return envVar, nil
}

func (c *CFClient) GetZones() {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones?name=%s&status=active&per_page=50&order=status&match=all", c.Domain)
	method := "GET"

	c.BuildRequest(method, url, nil)

	c.Request.Header.Add("Content-Type", "application/json")
	bearer := fmt.Sprintf("Bearer %s", c.Token)
	c.Request.Header.Add("Authorization", bearer)

	zonesResponse := c.SendRequest()

	var cfResponse CFResponse
	err := json.Unmarshal([]byte(zonesResponse), &cfResponse)
	if err != nil {
		log.Fatalln(err)
	}
	var zones = make(map[string]string)
	for _, result := range cfResponse.Result {
		zones[result.ID] = result.Name
	}
	c.Zones = zones
}

func (c *CFClient) ListDNSRecords() {
	for zoneID, zoneName := range c.Zones {
		if zoneName != c.Domain {
			continue
		}

		url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", zoneID)
		method := "GET"

		c.BuildRequest(method, url, nil)

		bearer := fmt.Sprintf("Bearer %s", c.Token)
		c.Request.Header.Add("Authorization", bearer)

		listResponse := c.SendRequest()

		var cfResponse CFResponseResultListDNS
		err := json.Unmarshal([]byte(listResponse), &cfResponse)
		if err != nil {
			log.Fatalln(err)
		}
		var dnsList = make(map[string]CFResponseListDNS)
		for _, dnsRow := range cfResponse.Result {
			dnsList[dnsRow.ID] = dnsRow
		}
		c.DNS = dnsList
	}
}

func (c *CFClient) CreateDNSRecord(createRecord CFCreateDNSRecord) {
	for zoneId, zoneName := range c.Zones {
		if zoneName == c.Domain {
			url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", zoneId)
			method := "POST"

			payload, err := json.Marshal(createRecord)
			if err != nil {
				log.Fatalln(err)
			}
			c.BuildRequest(method, url, bytes.NewReader(payload))

			bearer := fmt.Sprintf("Bearer %s", c.Token)
			c.Request.Header.Add("Authorization", bearer)
			c.Request.Header.Set("Content-Type", "application/json")
			log.Println(c.SendRequest())
		}
	}
}

func (c *CFClient) UpdateDNSRecord(updateRecord CFCreateDNSRecord) {
	for zoneId, zoneName := range c.Zones {
		if zoneName == c.Domain {
			for dnsId, dnsRow := range c.DNS {
				if dnsRow.Name == updateRecord.Name || dnsRow.Name == updateRecord.Name+"."+c.Domain {
					url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zoneId, dnsId)
					method := "PUT"

					payload, err := json.Marshal(updateRecord)
					if err != nil {
						fmt.Println(err)
						return
					}

					c.BuildRequest(method, url, bytes.NewReader(payload))

					bearer := fmt.Sprintf("Bearer %s", c.Token)
					c.Request.Header.Add("Authorization", bearer)
					c.Request.Header.Set("Content-Type", "application/json")
					log.Println(c.SendRequest())

					return
				}
			}
		}
	}
	log.Printf("Domain %s not found, can't be updated", updateRecord.Name+"."+c.Domain)
	log.Println("Switching to insert")
	c.CreateDNSRecord(updateRecord)
}

func (c *CFClient) BuildRequest(method string, url string, body io.Reader) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		log.Println(err)
		c.Error = err
		return
	}
	c.Request = req
}

func (c *CFClient) SendRequest() string {
	if c.Request == nil {
		log.Fatalln("Request must be build before sending")
	}
	res, err := c.Client.Do(c.Request)
	if err != nil {
		log.Println(err)
		c.Error = err

		return ""
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Println(err)
		c.Error = err
	}

	return string(body)
}

func (c *CFClient) WhatsMyPublicIP() {
	url := "http://ifconfig.me/ip"
	method := "GET"

	c.BuildRequest(method, url, nil)
	ip := c.SendRequest()
	c.MyPublicIP = ip
}

func (c *CFClient) DeleteDNSRecord(record string) {
	for zoneId, zoneName := range c.Zones {
		if zoneName == c.Domain {
			for dnsId, dnsRow := range c.DNS {
				if dnsRow.Name == record || dnsRow.Name == record+"."+c.Domain {
					url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zoneId, dnsId)
					method := "DELETE"

					c.BuildRequest(method, url, nil)
					log.Println(c.SendRequest())

					return
				}
			}
		}
	}
}

func encryptAES(key []byte, text string) string {
	c, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalln(err)
		os.Exit(2)
	}
	cText := make([]byte, len(text))
	c.Encrypt(cText, []byte(text))

	return hex.EncodeToString(cText)
}

func decryptAES(key []byte, cText string) string {
	cipherText, _ := hex.DecodeString(cText)
	c, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalln(err)
		os.Exit(2)
	}
	text := make([]byte, len(cipherText))
	c.Decrypt(text, cipherText)
	rString := string(text[:])

	return rString
}

func main() {
	var (
		domain    string
		subdomain string
		proxied   bool
		dnsType   string
		ttl       int
		priority  int
		list      bool
		delete    bool
	)

	flag.StringVar(&domain, "domain", "", "Domain name")
	flag.StringVar(&subdomain, "subdomain", "", "subdomain")
	flag.StringVar(&dnsType, "dns-type", "A", "DNS Type (A, CNAME...)")
	flag.BoolVar(&proxied, "proxied", false, "Proxied")
	flag.BoolVar(&list, "list", false, "List all DNS records")
	flag.BoolVar(&delete, "delete", false, "Delete DNS record")
	flag.IntVar(&ttl, "ttl", 3600, "TTL")
	flag.IntVar(&priority, "priority", 10, "priority")
	flag.Parse()

	cfToken, err := getEnvVar("CFToken")
	if err != nil {
		log.Fatalln(err)
	}

	if delete {
		if len(domain) == 0 || len(subdomain) == 0 {
			log.Println("To delete record you must pass domain and subdomain")
			flag.PrintDefaults()
			os.Exit(1)
		}
	}
	if !list && !delete {
		if len(domain) == 0 || len(subdomain) == 0 || len(dnsType) == 0 {
			log.Println("You must pass all arguments to insert/update record")
			flag.PrintDefaults()
			os.Exit(1)
		}
	}

	cf := CFClient{
		Client: &http.Client{},
		Token:  cfToken,
		Domain: domain,
	}
	cf.GetZones()
	cf.ListDNSRecords()
	if list {
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"ID", "Name", "Type", "Proxied?", "ttl", "modified_on"})
		for _, row := range cf.DNS {
			fRow := []string{row.ID, row.Name, row.Type, strconv.FormatBool(row.Proxied), strconv.Itoa(row.TTL), row.ModifiedOn}
			table.Append(fRow)
		}
		table.SetRowLine(true)
		table.SetRowSeparator("-")
		table.Render()

		os.Exit(0)
	}

	if delete {
		cf.DeleteDNSRecord(subdomain + "." + domain)
		os.Exit(0)
	}

	cf.WhatsMyPublicIP()

	// Create/Update DNS record
	dnsRecord := CFCreateDNSRecord{
		Type:     dnsType,
		Name:     subdomain,
		Proxied:  proxied,
		TTL:      ttl,
		Priority: priority,
		Content:  cf.MyPublicIP,
	}

	cf.UpdateDNSRecord(dnsRecord)
}
