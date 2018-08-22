package store

import (
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
)

//Controller ...
type Controller struct {
	Repository Repository
}

/* Middleware handler to handle all requests for authentication */
func AuthenticationMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		authorizationHeader := req.Header.Get("authorization")
		if authorizationHeader != "" {
			bearerToken := strings.Split(authorizationHeader, " ")
			if len(bearerToken) == 2 {
				token, error := jwt.Parse(bearerToken[1], func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("There was an error")
					}
					return []byte("secret"), nil
				})
				if error != nil {
					json.NewEncoder(w).Encode(Exception{Message: error.Error()})
					return
				}
				if token.Valid {
					log.Println("TOKEN WAS VALID")
					claims := token.Claims.(jwt.MapClaims)
					context.Set(req, "username", claims["username"])
					log.Println(token.Claims)
					next(w, req)
				} else {
					json.NewEncoder(w).Encode(Exception{Message: "Invalid authorization token"})
				}
			}
		} else {
			json.NewEncoder(w).Encode(Exception{Message: "An authorization header is required"})
		}
	})
}

// Get Authentication token GET /
func (c *Controller) GetToken(w http.ResponseWriter, req *http.Request) {
	var user User
	_ = json.NewDecoder(req.Body).Decode(&user)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"password": user.Password,
	})
	userFromDB := c.Repository.GetUserByUserName(user.Username)
	if userFromDB.Username == "" {
		http.Error(w, "Not authorized", 401)
		return
	}

	tokenString, error := token.SignedString([]byte("secret"))
	if error != nil {
		fmt.Println(error)
	}
	if !comparePasswords(userFromDB.Password, []byte(user.Password)) {
		http.Error(w, "Not authorized", 401)
		return
	}

	json.NewEncoder(w).Encode(JwtToken{Token: tokenString})
}

// Index GET /
func (c *Controller) Index(w http.ResponseWriter, r *http.Request) {
	products := c.Repository.GetProducts() // list of all products
	// log.Println(products)
	data, _ := json.Marshal(products)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
	return
}

// AddProduct POST /
func (c *Controller) AddProduct(w http.ResponseWriter, r *http.Request) {
	var product Product
	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 1048576)) // read the body of the request
	log.Println("USERNAME:", context.Get(r, "username"))
	log.Println(body)

	if err != nil {
		log.Fatalln("Error AddProduct", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if err := r.Body.Close(); err != nil {
		log.Fatalln("Error AddProduct", err)
	}

	if err := json.Unmarshal(body, &product); err != nil { // unmarshall body contents as a type Candidate
		w.WriteHeader(422) // unprocessable entity
		log.Println(err)
		if err := json.NewEncoder(w).Encode(err); err != nil {
			log.Fatalln("Error AddProduct unmarshalling data", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	log.Println(product)
	success := c.Repository.AddProduct(product) // adds the product to the DB
	if !success {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusCreated)
	return
}

// SearchProduct GET /
func (c *Controller) SearchProduct(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	log.Println(vars)

	query := vars["query"] // param query
	log.Println("Search Query - " + query)

	products := c.Repository.GetProductsByString(query)
	data, _ := json.Marshal(products)

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
	return
}

// UpdateProduct PUT /
func (c *Controller) UpdateProduct(w http.ResponseWriter, r *http.Request) {
	var product Product
	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 1048576)) // read the body of the request
	if err != nil {
		log.Fatalln("Error UpdateProduct", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if err := r.Body.Close(); err != nil {
		log.Fatalln("Error UpdateProduct", err)
	}

	if err := json.Unmarshal(body, &product); err != nil { // unmarshall body contents as a type Candidate
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.WriteHeader(422) // unprocessable entity
		if err := json.NewEncoder(w).Encode(err); err != nil {
			log.Fatalln("Error UpdateProduct unmarshalling data", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	log.Println(product.ID)
	success := c.Repository.UpdateProduct(product) // updates the product in the DB

	if !success {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	return
}

// GetProduct GET - Gets a single product by ID /
func (c *Controller) GetProduct(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	log.Println(vars)

	id := vars["id"] // param id
	log.Println(id)

	productid, err := strconv.Atoi(id)

	if err != nil {
		log.Fatalln("Error GetProduct", err)
	}

	product := c.Repository.GetProductById(productid)
	data, _ := json.Marshal(product)

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
	return
}

// DeleteProduct DELETE /
func (c *Controller) DeleteProduct(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	log.Println(vars)
	id := vars["id"] // param id
	log.Println(id)

	productid, err := strconv.Atoi(id)

	if err != nil {
		log.Fatalln("Error GetProduct", err)
	}

	if err := c.Repository.DeleteProduct(productid); err != "" { // delete a product by id
		log.Println(err)
		if strings.Contains(err, "404") {
			w.WriteHeader(http.StatusNotFound)
		} else if strings.Contains(err, "500") {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	return
}

// AddUser POST /
func (c *Controller) AddUser(w http.ResponseWriter, r *http.Request) {
	var user User
	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 1048576)) // read the body of the request
	log.Println(body)

	if err != nil {
		log.Fatalln("Error AddUser", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if err := r.Body.Close(); err != nil {
		log.Fatalln("Error AddUser", err)
	}

	if err := json.Unmarshal(body, &user); err != nil { // unmarshall body contents as a type Candidate
		w.WriteHeader(422) // unprocessable entity
		log.Println(err)
		if err := json.NewEncoder(w).Encode(err); err != nil {
			log.Fatalln("Error AddUser unmarshalling data", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	user.Password = hashAndSalt([]byte(user.Password))
	user.ID = user.Username
	success := c.Repository.AddUser(user) // adds the product to the DB
	if !success {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusCreated)
	return
}

func hashAndSalt(pwd []byte) string {
	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost)
	if err != nil {
		log.Println(err)
	}
	// GenerateFromPassword returns a byte slice so we need to
	// convert the bytes to a string and return it
	return string(hash)
}

func comparePasswords(hashedPwd string, plainPwd []byte) bool {
	// Since we'll be getting the hashed password from the DB it
	// will be a string so we'll need to convert it to a byte slice
	byteHash := []byte(hashedPwd)
	err := bcrypt.CompareHashAndPassword(byteHash, plainPwd)
	if err != nil {
		log.Println(err)
		return false
	}

	return true
}
