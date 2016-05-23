package icf

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	//"net/url"
	"path"
	"time"
)

const (
	defaultSessionLife    = 30 * time.Minute
	defaultSessionWindow  = 5 * time.Minute
	defaultRequestTimeout = 10 * time.Second
	defaultRetryCount     = 3
	defaultRetryTime      = 3 * time.Second
)

type Expiry struct {
	expiration time.Time
}

func (e *Expiry) SetExpiration(expiration time.Time, window time.Duration) {
	e.expiration = expiration
	if window > 0 {
		e.expiration = e.expiration.Add(-window)
	}
}

func (e *Expiry) IsExpired() bool {
	return e.expiration.Before(time.Now())
}

type SessionParams struct {
	Token   string
	Cookies []*http.Cookie
}

type Session struct {
	Expiry
	client     *Client
	life       time.Duration
	retryCount uint
	retryTime  time.Duration
	params     SessionParams
	hclient    *http.Client
	//url        *url.URL
	req  *http.Request
	resp *http.Response
}

const (
	create uint = iota
	read
	update
	remove
	invalid
)

var method = []string{"POST", "GET", "POST", "DELETE"}

func NewSession(client *Client, life time.Duration) (session *Session, err error) {
	if life <= 0 {
		life = defaultSessionLife
	}
	session = &Session{
		client:     client,
		life:       life,
		retryCount: defaultRetryCount,
		retryTime:  defaultRetryTime,
		hclient: &http.Client{
			Timeout: defaultRequestTimeout,
		},
	}

	if client.config.ServerCert != "" {
		roots := x509.NewCertPool()
		ok := roots.AppendCertsFromPEM([]byte(client.config.ServerCert))
		if !ok {
			log.Printf("[Error] Invalid Server Cert\n", err)
			err = fmt.Errorf("Invalid Server Cert")
			return
		}

		session.hclient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: roots,
			},
		}
	}

	/*
		session.url = &url.URL{
			Scheme: "https",
			Host:   client.config.EndPoint,
		}
	*/

	err = session.Open()

	return
}

func (s *Session) SetRequest(oper uint, path string, data []byte) (err error) {
	url := s.client.config.Url(path)
	if s.req, err = http.NewRequest(method[oper], url, bytes.NewBuffer(data)); err != nil {
		return
	}
	s.req.Header.Add("Content-Type", "application/json")
	if s.params.Token != "" {
		s.req.Header.Add("x_icfb_token", s.params.Token)
	}
	if s.params.Cookies != nil {
		for _, cookie := range s.params.Cookies {
			s.req.AddCookie(cookie)
		}
	}
	return
}

func (s *Session) Renew() (err error) {
	if s.IsExpired() {
		if err = s.Open(); err != nil {
			return
		}
	}
	return
}

func (s *Session) Do() (statusCode int, status string, data []byte, err error) {
	s.resp, err = s.hclient.Do(s.req)
	if err != nil {
		return
	}
	status = s.resp.Status
	statusCode = s.resp.StatusCode
	data, err = ioutil.ReadAll(s.resp.Body)
	return
}

func (s *Session) Open() (err error) {
	var data []byte
	s.SetExpiration(time.Now().Add(s.life), defaultSessionWindow)
	if data, err = json.Marshal(s.client.config.Credentials); err != nil {
		return
	}
	if err = s.SetRequest(create, "token", data); err != nil {
		return
	}
	if _, _, _, err = s.Do(); err != nil {
		return
	}
	s.params.Token = s.resp.Header.Get("x_icfb_token")
	s.params.Cookies = s.resp.Cookies()
	_, err = ioutil.ReadAll(s.resp.Body)
	return
}

func (s *Session) Close() (err error) {
	var data []byte
	if data, err = json.Marshal(s.client.config.Credentials); err != nil {
		return
	}
	if err = s.SetRequest(create, "logout", data); err != nil {
		return
	}
	if _, _, _, err = s.Do(); err != nil {
		return
	}
	return
}

const (
	StatusInProgress       = "In_Progress"
	StatusCreateInProgress = "Create_In_Progress"
	StatusDeleteInProgress = "Delete_In_Progress"
	StatusSuccess          = "Success"
	StatusDeleted          = "Deleted"
)

type InstanceNicInfo struct {
	Index   uint   `json:"nic_index"`
	Dhcp    bool   `json:"is_dhcp"`
	Network string `json:"network_oid"`
	Ip      string `json:"ip_address,omitempty"`
}

type instancePowerStatus struct {
	Status string `json:"power_status"`
}

type instanceProviderIP struct {
	Private string `json:"private"`
	Public  string `json:"public"`
}

type instanceOperInfo struct {
	Power      instancePowerStatus `json:"operational_status"`
	ProviderIP instanceProviderIP  `json:"provider_ip_address"`
}

type instanceNetworkInfo struct {
	Nics []InstanceNicInfo `json:"nics"`
}

type instanceResourceInfo struct {
	Network instanceNetworkInfo `json:"network"`
}

type refObjProperties struct {
	Name string `json:"name"`
	Oid  string `json:"oid"`
}

type refObjInfo struct {
	Properties refObjProperties `json:"properties"`
}

type instanceProperties struct {
	Name           string               `json:"name,omitempty"`
	Oid            string               `json:"oid"`
	ProviderAccess bool                 `json:"enable_provider_services_access,omitempty"`
	Oper           instanceOperInfo     `json:"operational_information"`
	Resources      instanceResourceInfo `json:"resource_information"`
	VdcInfo        refObjInfo           `json:"vdc_summary"`
	CatalogInfo    refObjInfo           `json:"catalog_item_summary"`
	Status         string               `json:"status"`
}

type instanceValue struct {
	Properties instanceProperties `json:"properties"`
}

type instanceMsg struct {
	Instances []instanceValue `json:"value"`
}

type instanceNewMsg struct {
	Name           string            `json:"name,omitempty"`
	Vdc            string            `json:"vdc_oid"`
	Catalog        string            `json:"catalog_oid"`
	ProviderAccess bool              `json:"enable_provider_services_access,omitempty"`
	Nics           []InstanceNicInfo `json:"nic_configurations"`
}

type links struct {
	Resource string `json:"new_resource"`
}

type statusMsg struct {
	Code     uint     `json:"code"`
	Messages []string `json:"messages"`
	Links    links    `json:"links,omitempty"`
}

type instanceStatusResp struct {
	Success *statusMsg `json:"success,omitempty"`
	Failure *statusMsg `json:"error,omitempty"`
}

type Instance struct {
	Name           string            `json:"name,omitempty"`
	Oid            string            `json:"oid,omitempty"`
	Vdc            string            `json:"vdc_oid"`
	Catalog        string            `json:"catalog_oid"`
	ProviderAccess bool              `json:"enable_provider_services_access"`
	Nics           []InstanceNicInfo `json:"networks"`
	PublicIp       string            `json:"public_ip"`
	PrivateIp      string            `json:"private_ip"`
	Status         string
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Config struct {
	Credentials Credentials
	EndPoint    string
	Protocol    string
	Root        string
	ServerCert  string
}

func (c Config) Url(path string) (url string) {
	url = c.Protocol + "://" + c.EndPoint + "/" + c.Root + "/" + path
	return
}

type Client struct {
	config Config
}

func NewClient(config *Config) (c *Client) {
	c = &Client{
		config: *config,
	}
	return
}

func instancePropertiesToValue(resp instanceProperties) (inst *Instance, err error) {
	inst = &Instance{
		Name:           resp.Name,
		Oid:            resp.Oid,
		ProviderAccess: resp.ProviderAccess,
		Vdc:            resp.VdcInfo.Properties.Oid,
		Catalog:        resp.CatalogInfo.Properties.Oid,
		PublicIp:       resp.Oper.ProviderIP.Public,
		PrivateIp:      resp.Oper.ProviderIP.Private,
		Status:         resp.Status,
	}
	inst.Nics = make([]InstanceNicInfo, len(resp.Resources.Network.Nics))
	copy(inst.Nics, resp.Resources.Network.Nics)
	return
}

func instanceRespToValues(resp instanceMsg) (instances []*Instance, err error) {
	count := len(resp.Instances)
	if count < 1 {
		err = fmt.Errorf("No instances found\n")
		return
	}
	instances = make([]*Instance, count, count)
	for index, instance := range resp.Instances {
		if instances[index], err = instancePropertiesToValue(instance.Properties); err != nil {
			instances = nil
			return
		}
	}
	return
}

func (c *Client) do(oper uint, object string, reqData []byte) (rspData []byte, err error) {
	var sc int
	var scMsg string

	session, err := NewSession(c, 0)
	if err != nil {
		if session != nil {
			session.Close()
		}
		log.Printf("Error creating new session : Error = (%v)\n", err)
		return
	}
	defer func() {
		session.Close()
	}()
	if err = session.SetRequest(oper, object, reqData); err != nil {
		return
	}
	for i := uint(0); i < (session.retryCount + 1); i++ {
		if sc, scMsg, rspData, err = session.Do(); err != nil {
			return
		}
		if sc == 409 && i != session.retryCount {
			if err = session.SetRequest(oper, object, reqData); err != nil {
				return
			}
			rand.Seed(int64(time.Now().Nanosecond()))
			retryTime := time.Duration((1000 + rand.Intn(3000))) * time.Millisecond
			time.Sleep(retryTime)
		} else {
			break
		}
	}
	if sc >= 300 || sc < 100 {
		err = fmt.Errorf("%v", scMsg)
		return
	}
	return
}

func (c *Client) GetInstance(oid string) (instance *Instance, err error) {
	var resp instanceMsg
	var data []byte
	var instances []*Instance

	data, err = c.do(read, "instances"+"/"+oid, nil)
	if err != nil {
		log.Printf("Error reading instance (%s): Error = (%v)\n", oid, err)
		return
	}
	if err = json.Unmarshal(data, &resp); err != nil {
		return
	}
	if instances, err = instanceRespToValues(resp); err != nil {
		return
	}
	instance = instances[0]
	return
}

func (c *Client) GetInstances() (instances []*Instance, err error) {
	var resp instanceMsg
	var data []byte

	data, err = c.do(read, "instances", nil)
	if err != nil {
		log.Printf("Error reading all instances : Error = (%v)\n", err)
		return
	}
	if err = json.Unmarshal(data, &resp); err != nil {
		return
	}
	if instances, err = instanceRespToValues(resp); err != nil {
		return
	}
	return
}

func newInstanceMsg(instance *Instance) (msg *instanceNewMsg, err error) {
	msg = &instanceNewMsg{
		Name:           instance.Name,
		Vdc:            instance.Vdc,
		Catalog:        instance.Catalog,
		ProviderAccess: instance.ProviderAccess,
	}
	msg.Nics = make([]InstanceNicInfo, len(instance.Nics))
	copy(msg.Nics, instance.Nics)
	return
}

func (c *Client) CreateInstance(instance *Instance) (newInstance *Instance, err error) {
	var resp instanceStatusResp
	var req *instanceNewMsg
	var rspData, reqData []byte

	if req, err = newInstanceMsg(instance); err != nil {
		return
	}
	if reqData, err = json.Marshal(req); err != nil {
		return
	}
	rspData, err = c.do(create, "instances", reqData)
	if err != nil {
		log.Printf("Error Creating instance (%v) : Error = (%v)\n",
			instance, err)
		return
	}
	if err = json.Unmarshal(rspData, &resp); err != nil {
		return
	}
	if resp.Success == nil {
		err = fmt.Errorf("No Success code found")
		return
	}
	oid := path.Base(resp.Success.Links.Resource)

	if newInstance, err = c.GetInstance(oid); err != nil {
		return
	}

	return
}

func (c *Client) DeleteInstance(oid string) (err error) {
	var data []byte
	var resp instanceStatusResp

	data, err = c.do(remove, "instances"+"/"+oid, nil)
	if err != nil {
		log.Printf("Error Deleting instance (%s) : Error = (%v)\n",
			oid, err)
		return
	}
	if err = json.Unmarshal(data, &resp); err != nil {
		return
	}
	if resp.Success == nil {
		err = fmt.Errorf("No Success code found")
		return
	}

	return
}
