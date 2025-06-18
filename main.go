package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/bcrypt"
)

type LogIn struct {
	Name     string
	Password string
}

type Auth struct {
	ID      int
	Session string
}

type auther interface {
	data() (int, string)
}

type parentPost struct {
	ID          int
	UserID      int
	Username    string
	Contents    string
	Time        int
	Attachments []attachment
}

type post struct {
	Parent      *parentPost
	ID          int
	Contents    string
	Time        int
	Replies     int
	Username    string
	UserID      int
	Attachments []attachment
}

type userData struct {
	Name   string
	Status string
	ID     int
}

type followData struct {
	ID     int
	Name   string
	Status string
}

type message struct {
	Contents    string
	Time        int
	From        int
	Attachments []attachment
}

type chat struct {
	ID       int
	Name     string
	Time     int
	Contents string
}

type player struct {
	c    *websocket.Conn
	X    int
	Y    int
	Name string
}

type fileInfo struct {
	ID   int
	Name string
	URL  string
	Type int
}

type attachment struct {
	URL  string
	Type int
}

type taginfo struct {
	Name  string
	Posts int
}

func (a Auth) data() (int, string) {
	return a.ID, a.Session
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func randStr(size int) (string, error) {
	t := make([]byte, size)
	_, err := rand.Read(t)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(t), nil
}

func httpErr(w http.ResponseWriter, err string) {
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprintf(w, `{"err":"`+err+`"}`)
}

func wsErr(c *websocket.Conn, msg string) {
	c.WriteMessage(websocket.TextMessage, []byte(`{"err":"`+msg+`"}`))
}

func sockauth(c *websocket.Conn, db *sql.DB) (Auth, error) {
	var a Auth
	_, msg, err := c.ReadMessage()
	if err != nil {
		return a, errors.New("error getting authentication data")
	}
	err = json.Unmarshal(msg, &a)
	if err != nil {
		return a, errors.New("error parsing authentication data")
	}
	ok := auth(db, a)
	if !ok {
		return a, errors.New("authentication error")
	}
	return a, nil
}

func auth(db *sql.DB, a auther) bool {
	var SqlSession sql.NullString
	ID, Session := a.data()
	err := db.QueryRow("SELECT session FROM user WHERE id = ?", ID).Scan(&SqlSession)
	return err == nil && SqlSession.Valid && SqlSession.String == Session
}

func auth2(db *sql.DB, id string, session string) bool {
	var SqlSession sql.NullString
	err := db.QueryRow("SELECT session FROM user WHERE id = ?", id).Scan(&SqlSession)
	return err == nil && SqlSession.Valid && SqlSession.String == session
}

func userNameExists(db *sql.DB, name string) (bool, error) {
	err := db.QueryRow("SELECT name FROM user WHERE name = ?", name).Scan(&name)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func handle(in func(w http.ResponseWriter, r *http.Request) error) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		err := in(w, r)
		if err != nil {
			httpErr(w, err.Error())
		}
	}
}

func alphanum(str string) bool {
	return regexp.MustCompile(`^[a-z0-9]*$`).MatchString(str)
}

func cors(db *sql.DB, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.Method == "OPTIONS" {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, X-Auth-Token, Authorization")
			w.Header().Set("Content-Type", "application/json")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func getPostAttachments(db *sql.DB, post int) ([]attachment, error) {
	e := errors.New
	rows2, err := db.Query("SELECT url, type FROM post_attachment JOIN file ON post_attachment.file = file.id WHERE post=?", post)
	defer rows2.Close()
	if err != nil {
		return nil, e("could not get post attachments")
	}

	var As []attachment
	for rows2.Next() {
		a := attachment{}
		if err := rows2.Scan(&a.URL, &a.Type); err != nil {
			return nil, e("could not scan attacment")
		}
		As = append(As, a)
	}
	return As, nil
}

func scanPostList(db *sql.DB, rows *sql.Rows) ([]post, error) {
	e := errors.New
	var ps []post
	for rows.Next() {
		p := post{}
		var parent *int
		if err := rows.Scan(&p.ID, &p.Contents, &p.Time, &parent, &p.Replies, &p.Username, &p.UserID); err != nil {
			return nil, e("error reading posts")
		}

		var err error
		p.Attachments, err = getPostAttachments(db, p.ID)
		if err != nil {
			return nil, err
		}

		if parent != nil {
			pp := new(parentPost)
			err = db.QueryRow("SELECT post.id, contents, time, user_id, name FROM post LEFT JOIN user ON user_id = user.id WHERE post.id=?", *parent).Scan(&pp.ID, &pp.Contents, &pp.Time, &pp.UserID, &pp.Username)
			if err != nil {
				return nil, e("error reading parent post")
			}
			rows2, err := db.Query("SELECT url, type FROM post_attachment JOIN file ON post_attachment.file = file.id WHERE post=?", pp.ID)
			if err != nil {
				return nil, e("could not get post attachments")
			}
			for rows2.Next() {
				a := attachment{}
				if err := rows2.Scan(&a.URL, &a.Type); err != nil {
					return nil, e("could not scan attacment")
				}
				pp.Attachments = append(pp.Attachments, a)
			}
			p.Parent = pp
		}
		ps = append(ps, p)
	}
	return ps, nil
}

func scanPosts(db *sql.DB, rows *sql.Rows) ([]byte, error) {
	e := errors.New
	var posts struct {
		Count int
		Ps    []post
	}

	Ps, err := scanPostList(db, rows)
	if err != nil {
		return nil, err
	}
	posts.Ps = Ps
	posts.Count = len(Ps)

	j, err := json.Marshal(posts)
	if err != nil {
		return nil, e("error sending posts")
	}
	return j, nil
}

func main() {
	db, err := sql.Open("sqlite3", "db")
	check(err)
	defer db.Close()

	e := errors.New
	jErr := e("error reading json body")
	rErr := e("error generating response")
	aErr := e("authentication error")

	conns := make(map[int]*websocket.Conn)
	var regmx sync.Mutex
	var loungemx sync.Mutex
	var msgmx sync.Mutex
	var hashtagmx sync.Mutex

	mux := http.NewServeMux()
	mux.HandleFunc("POST /login/", handle(func(w http.ResponseWriter, r *http.Request) error {
		var l LogIn
		err := json.NewDecoder(r.Body).Decode(&l)
		if err != nil {
			return jErr
		}

		var password string
		var id int
		err = db.QueryRow("SELECT id, password FROM user WHERE name = ?", l.Name).Scan(&id, &password)
		if err != nil {
			if err == sql.ErrNoRows {
				return e("could not find user, check username")
			} else {
				return e("error findning user")
			}
		}

		if err := bcrypt.CompareHashAndPassword([]byte(password), []byte(l.Password)); err != nil {
			return e("error verifying password")
		}

		session, err := randStr(128)
		if err != nil {
			return e("could not create new session")
		}
		_, err = db.Exec("UPDATE user SET session = ? WHERE id = ?", session, id)
		if err != nil {
			return e("error updating session")
		}

		a := Auth{id, session}
		j, err := json.Marshal(a)
		if err != nil {
			return rErr
		}
		fmt.Fprintf(w, string(j))

		return nil
	}))

	mux.HandleFunc("POST /register/", handle(func(w http.ResponseWriter, r *http.Request) error {
		var l LogIn
		err := json.NewDecoder(r.Body).Decode(&l)
		if err != nil {
			return jErr
		}
		if len(l.Name) < 3 || len(l.Name) > 16 {
			return e("name length ought to be between 3 and 16 charaters")
		}

		if ok := alphanum(l.Name); !ok {
			return e("username should be alphanumeric and lowercase")
		}

		if len(l.Password) < 10 || len(l.Password) > 30 {
			return e("password length ought to be between 10 and 30 charaters")
		}

		regmx.Lock()
		defer regmx.Unlock()
		ex, err := userNameExists(db, l.Name)
		if err != nil {
			return e("error checking user existence")
		}

		if ex {
			return e("user with this username already exists")
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(l.Password), 14)
		if err != nil {
			return e("error hashing password")
		}

		_, err = db.Exec("INSERT INTO user(name, password, status) VALUES(?,?,'')", l.Name, hash)
		if err != nil {
			return e("error creating user")
		}

		return nil
	}))

	mux.HandleFunc("POST /follow/", handle(func(w http.ResponseWriter, r *http.Request) error {
		var b struct {
			Auth
			Whom   int
			Action bool //true=follow, false=unfollow
		}
		err := json.NewDecoder(r.Body).Decode(&b)
		if err != nil {
			return jErr
		}
		ok := auth(db, b)
		if !ok {
			return aErr
		}

		err = db.QueryRow("SELECT id FROM user WHERE id = ?", b.Whom).Scan(&b.Whom)
		if err != nil {
			if err == sql.ErrNoRows {
				return e("user does not exist")
			}
			return e("error checking if user exists")
		}

		if b.Action {
			if b.ID == b.Whom {
				return e("cannot follow yourself")
			}
			err = db.QueryRow("SELECT followee FROM follow WHERE followee = ? and follower = ?", b.Whom, b.ID).Scan(&b.Whom)
			if err != nil {
				if err != sql.ErrNoRows {
					return e("error checking if already following")
				}
			} else {
				return e("already following")
			}

			_, err = db.Exec("INSERT INTO follow(follower,followee) VALUES(?,?)", b.ID, b.Whom)
			if err != nil {
				return e("error following")
			}
		} else {
			_, err = db.Exec("DELETE FROM follow WHERE follower=? AND followee=?", b.ID, b.Whom)
			if err != nil {
				return e("error unfollowing")
			}
		}
		return nil
	}))

	mux.HandleFunc("POST /post/", handle(func(w http.ResponseWriter, r *http.Request) error {
		var b struct {
			Auth
			Contents    string
			ParentID    *int
			Attachments []string
		}
		err := json.NewDecoder(r.Body).Decode(&b)
		if err != nil {
			return jErr
		}
		ok := auth(db, b)
		if !ok {
			return aErr
		}
		if l := len(b.Contents); l > 1024 || l < 1 && len(b.Attachments) == 0 {
			return e("content should be no more than 1024 characters and no less than 1")
		}

		ctx := context.Background()
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return e("could not start transaction")
		}
		defer tx.Rollback()

		postrow, err := tx.ExecContext(ctx, "INSERT INTO post(user_id, contents, time, parent_post_id) VALUES(?,?,unixepoch('now'),?)", b.ID, b.Contents, b.ParentID)
		if err != nil {
			fmt.Println(err)
			return e("posting error")
		}

		postid, err := postrow.LastInsertId()
		if err != nil {
			return e("error getting post id")
		}

		rx := regexp.MustCompile(`#[^ \t\n]{1,256}`)
		matches := rx.FindAllStringSubmatch(b.Contents, -1)
		for _, v := range matches {
			m := v[0][1:]
			var tagid int64

			hashtagmx.Lock()
			defer hashtagmx.Unlock()
			err := db.QueryRow("SELECT id FROM tag WHERE name=?", m).Scan(&tagid)
			if err != nil {
				if err == sql.ErrNoRows {
					tagrow, err := tx.ExecContext(ctx, "INSERT INTO tag(name) VALUES(?)", m)
					if err != nil {
						return e("error creating hashtag")
					}
					tagid, err = tagrow.LastInsertId()
					if err != nil {
						return e("error getting tag id")
					}
				} else {
					return e("error checking hashtag existence")
				}
			}

			_, err = tx.ExecContext(ctx, "INSERT INTO post_tag(post, tag) VALUES(?,?)", postid, tagid)
			if err != nil {
				return e("error attaching post to tag")
			}
		}

		for _, a := range b.Attachments {
			_, err = tx.ExecContext(ctx, "INSERT INTO post_attachment(post, file) SELECT ?, file.id FROM file WHERE url=?", postid, a)
			if err != nil {
				return e("error attaching one of the attachments")
			}
		}
		if err := tx.Commit(); err != nil {
			fmt.Println("could not commit")
		}

		fmt.Fprintf(w, "%d", postid)
		return nil
	}))

	mux.HandleFunc("POST /newstatus/", handle(func(w http.ResponseWriter, r *http.Request) error {
		var b struct {
			Auth
			Contents string
		}
		err := json.NewDecoder(r.Body).Decode(&b)
		if err != nil {
			return jErr
		}
		ok := auth(db, b)
		if !ok {
			return aErr
		}
		if len(b.Contents) > 128 {
			return e("status should be no more than 128 characters")
		}

		_, err = db.Exec("UPDATE user SET status=? WHERE id=?", b.Contents, b.ID)
		if err != nil {
			return e("error changing status")
		}
		return nil
	}))

	mux.HandleFunc("POST /user/", handle(func(w http.ResponseWriter, r *http.Request) error {
		var b struct {
			Auth
			UserID int
		}
		err := json.NewDecoder(r.Body).Decode(&b)
		if err != nil {
			return jErr
		}
		ok := auth(db, b)
		if !ok {
			return aErr
		}

		var u struct {
			Status  string
			Name    string
			IFollow bool
			Follows bool
			Online  bool
		}

		err = db.QueryRow("SELECT status, name, myfollow.id IS NOT NULL, hisfollow.id IS NOT NULL FROM user LEFT JOIN follow AS myfollow ON myfollow.follower=? AND myfollow.followee=? LEFT JOIN follow AS hisfollow ON hisfollow.follower = ? AND hisfollow.followee = ?  WHERE user.id=?", b.ID, b.UserID, b.UserID, b.ID, b.UserID).Scan(&u.Status, &u.Name, &u.IFollow, &u.Follows)
		if err != nil {
			fmt.Println(err)
			return e("error finding user")
		}
		_, online := conns[b.UserID]
		u.Online = online
		j, err := json.Marshal(u)
		if err != nil {
			return e("error sending user data")
		}
		w.Write([]byte(j))
		return nil
	}))

	mux.HandleFunc("POST /posts/", handle(func(w http.ResponseWriter, r *http.Request) error {
		var b struct {
			Auth
			UserID int
			Page   int
		}
		err := json.NewDecoder(r.Body).Decode(&b)
		if err != nil {
			return jErr
		}
		ok := auth(db, b)
		if !ok {
			return aErr
		}

		rows, err := db.Query("SELECT post.id, post.contents, post.time, post.parent_post_id, count(child.id), user.name, post.user_id FROM post LEFT JOIN post AS child ON post.id = child.parent_post_id JOIN user ON post.user_id=user.id WHERE post.user_id=? GROUP BY post.id ORDER BY post.time DESC LIMIT 20 OFFSET ?", b.UserID, b.Page*20)
		if err != nil {
			fmt.Println(err)
			return e("error getting posts")
		}
		defer rows.Close()

		j, err := scanPosts(db, rows)
		if err != nil {
			return err
		}
		w.Write(j)
		return nil
	}))

	mux.HandleFunc("POST /replies/", handle(func(w http.ResponseWriter, r *http.Request) error {
		var b struct {
			Auth
			PostID int
			Page   int
		}
		err := json.NewDecoder(r.Body).Decode(&b)
		if err != nil {
			return jErr
		}
		ok := auth(db, b)
		if !ok {
			return aErr
		}

		var posts struct {
			UserID      int
			Time        int
			Name        string
			Contents    string
			Count       int
			Parent      *parentPost
			Ps          []post
			Attachments []attachment
		}

		var parent *int
		err = db.QueryRow("SELECT user_id, time, user.name, contents, parent_post_id FROM post JOIN user ON user.id=user_id WHERE post.id=?", b.PostID).Scan(&posts.UserID, &posts.Time, &posts.Name, &posts.Contents, &parent)
		if err != nil {
			return e("error getting post")
		}

		if parent != nil {
			pp := new(parentPost)
			err = db.QueryRow("SELECT post.id, contents, time, user_id, name FROM post LEFT JOIN user ON user_id = user.id WHERE post.id=?", *parent).Scan(&pp.ID, &pp.Contents, &pp.Time, &pp.UserID, &pp.Username)
			if err != nil {
				return e("error reading parent post")
			}
			posts.Parent = pp
			pp.Attachments, err = getPostAttachments(db, pp.ID)
			if err != nil {
				return err
			}
		}

		posts.Attachments, err = getPostAttachments(db, b.PostID)
		if err != nil {
			return e("error getting OP attachment")
		}

		rows, err := db.Query("SELECT post.id, post.contents, post.time, post.parent_post_id, count(child.id), user.name, post.user_id FROM post JOIN post AS parent ON post.parent_post_id = parent.id LEFT JOIN post AS child ON child.parent_post_id = post.id JOIN user ON post.user_id = user.id WHERE parent.id=? GROUP BY post.id ORDER BY post.time DESC LIMIT 20 OFFSET ?", b.PostID, b.Page*20)
		if err != nil {
			return e("error getting replies")
		}

		defer rows.Close()
		Ps, err := scanPostList(db, rows)
		if err != nil {
			return err
		}
		posts.Ps = Ps
		posts.Count = len(Ps)

		j, err := json.Marshal(posts)
		if err != nil {
			return e("error sending replies")
		}
		w.Write([]byte(j))
		return nil
	}))

	mux.HandleFunc("POST /feed/", handle(func(w http.ResponseWriter, r *http.Request) error {
		var b struct {
			Auth
			Page int
		}
		err := json.NewDecoder(r.Body).Decode(&b)
		if err != nil {
			return jErr
		}
		ok := auth(db, b)
		if !ok {
			return aErr
		}

		rows, err := db.Query(`
SELECT
	post.id, post.contents, post.time, post.parent_post_id,
	count(child.id), user.name, post.user_id
FROM post
	JOIN user ON user.id = post.user_id
	LEFT JOIN follow ON post.user_id = follow.followee AND follow.followee != ?
	LEFT JOIN post AS child ON child.parent_post_id = post.id
WHERE follow.follower = ? OR post.user_id=?
GROUP BY post.id
ORDER BY post.time DESC
LIMIT 20 OFFSET ?`, b.ID, b.ID, b.ID, b.Page*20)

		if err != nil {
			fmt.Println(err)
			return e("error getting feed")
		}
		defer rows.Close()

		j, err := scanPosts(db, rows)
		if err != nil {
			return err
		}
		w.Write(j)
		return nil
	}))

	mux.HandleFunc("POST /newusers/", handle(func(w http.ResponseWriter, r *http.Request) error {
		var b struct {
			Auth
			Page int
		}
		err := json.NewDecoder(r.Body).Decode(&b)
		if err != nil {
			return jErr
		}
		ok := auth(db, b)
		if !ok {
			return aErr
		}

		var newUsers struct {
			Count int
			Us    []userData
		}

		rows, err := db.Query("SELECT id, name, status FROM user ORDER BY id DESC LIMIT 20 OFFSET ?", b.Page*20)
		if err != nil {
			return e("error getting new users")
		}

		defer rows.Close()
		newUsers.Count = 0
		for rows.Next() {
			u := userData{}
			if err := rows.Scan(&u.ID, &u.Name, &u.Status); err != nil {
				return e("error reading new users")
			}
			newUsers.Us = append(newUsers.Us, u)
			newUsers.Count++
		}

		j, err := json.Marshal(newUsers)
		if err != nil {
			return e("error sending new users")
		}
		w.Write([]byte(j))
		return nil
	}))

	mux.HandleFunc("POST /followers/", handle(func(w http.ResponseWriter, r *http.Request) error {
		var b struct {
			Auth
			UserID int
			Page   int
		}
		err := json.NewDecoder(r.Body).Decode(&b)
		if err != nil {
			return jErr
		}
		ok := auth(db, b)
		if !ok {
			return aErr
		}

		var follows struct {
			Count int
			Total int
			Fs    []followData
		}

		err = db.QueryRow("SELECT count(id) FROM follow WHERE followee=?", b.UserID).Scan(&follows.Total)
		if err != nil {
			return e("could not get follower count")
		}

		rows, err := db.Query("SELECT follower, name, status FROM follow JOIN user ON user.id = follower WHERE followee=? ORDER BY user.id DESC LIMIT 20 OFFSET ?", b.UserID, b.Page*20)
		if err != nil {
			fmt.Println(err)
			return e("error getting followers")
		}

		defer rows.Close()
		follows.Count = 0
		for rows.Next() {
			f := followData{}
			if err := rows.Scan(&f.ID, &f.Name, &f.Status); err != nil {
				return e("error reading followers")
			}
			follows.Fs = append(follows.Fs, f)
			follows.Count++
		}

		j, err := json.Marshal(follows)
		if err != nil {
			return e("error sending followers")
		}
		w.Write([]byte(j))
		return nil
	}))

	mux.HandleFunc("POST /following/", handle(func(w http.ResponseWriter, r *http.Request) error {
		var b struct {
			Auth
			UserID int
			Page   int
		}
		err := json.NewDecoder(r.Body).Decode(&b)
		if err != nil {
			return jErr
		}
		ok := auth(db, b)
		if !ok {
			return aErr
		}

		var following struct {
			Count int
			Total int
			Fs    []followData
		}

		err = db.QueryRow("SELECT count(id) FROM follow WHERE follower=?", b.UserID).Scan(&following.Total)
		if err != nil {
			return e("could not get count of users following")
		}

		rows, err := db.Query("SELECT followee, name, status FROM follow JOIN user ON user.id = followee WHERE follower=? ORDER BY user.id DESC LIMIT 20 OFFSET ?", b.UserID, b.Page*20)
		if err != nil {
			return e("error getting users you follow")
		}

		defer rows.Close()
		following.Count = 0
		for rows.Next() {
			f := followData{}
			if err := rows.Scan(&f.ID, &f.Name, &f.Status); err != nil {
				return e("error reading users you follow")
			}
			following.Fs = append(following.Fs, f)
			following.Count++
		}

		j, err := json.Marshal(following)
		if err != nil {
			return e("error sending users you follow")
		}
		w.Write([]byte(j))
		return nil
	}))

	var upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
	mux.HandleFunc("POST /messages/", handle(func(w http.ResponseWriter, r *http.Request) error {
		var b struct {
			Auth
			UserID int
			Page   int
		}
		err := json.NewDecoder(r.Body).Decode(&b)
		if err != nil {
			return jErr
		}
		ok := auth(db, b)
		if !ok {
			return aErr
		}

		var messages struct {
			Count int
			Ms    []message
		}

		rows, err := db.Query("SELECT id, contents, time, from_ FROM message WHERE from_=? and to_=? or from_=? and to_=? ORDER BY time DESC LIMIT 20 OFFSET ?", b.UserID, b.ID, b.ID, b.UserID, b.Page*20)
		if err != nil {
			fmt.Println(err)
			return e("could not get messages")
		}

		defer rows.Close()
		messages.Count = 0
		for rows.Next() {
			m := message{}
			var msgid int
			if err := rows.Scan(&msgid, &m.Contents, &m.Time, &m.From); err != nil {
				return e("error reading messages")
			}
			rows2, err := db.Query("SELECT url, type FROM message_attachment JOIN file ON message_attachment.file=file.id WHERE message=?", msgid)
			if err != nil {
				return e("error getting attachments")
			}
			for rows2.Next() {
				at := attachment{}
				if err := rows2.Scan(&at.URL, &at.Type); err != nil {
					return e("error reading one of the attachments")
				}
				m.Attachments = append(m.Attachments, at)
			}
			messages.Ms = append(messages.Ms, m)
			messages.Count++
		}

		j, err := json.Marshal(messages)
		if err != nil {
			return e("error sending messages")
		}
		w.Write([]byte(j))
		return nil
	}))

	mux.HandleFunc("/messagesock/", func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()

		a, err := sockauth(c, db)
		if err != nil {
			wsErr(c, err.Error())
			return
		}

		//ok, _ = conns[a.ID] ???
		msgmx.Lock()
		conns[a.ID] = c
		msgmx.Unlock()

		defer func() {
			msgmx.Lock()
			delete(conns, a.ID)
			msgmx.Unlock()
		}()

		var msgin struct {
			To          int
			Contents    string
			Attachments []string
		}

		for {
			t, msg, err := c.ReadMessage()
			if err != nil {
				wsErr(c, "error reading message")
				break
			}
			if t == websocket.CloseMessage {
				break
			}
			err = json.Unmarshal(msg, &msgin)
			if err != nil {
				wsErr(c, "error parsing message")
				continue
			}

			if l := len(msgin.Contents); l < 1 && len(msgin.Attachments) == 0 || l > 1024 {
				wsErr(c, "message should be beetween 1 and 1024 characters")
				continue
			}

			if len(msgin.Attachments) > 3 {
				wsErr(c, "you cannot attach more than 3 files")
				continue
			}

			err = db.QueryRow("SELECT id FROM user WHERE id=?", msgin.To).Scan(&msgin.To)
			if err != nil {
				if err == sql.ErrNoRows {
					wsErr(c, "user does not exist")
				} else {
					wsErr(c, "error checking user existence")
				}
				continue
			}

			ctx := context.Background()
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				wsErr(c, "could not start transaction")
				continue
			}
			defer tx.Rollback()

			row, err := tx.ExecContext(ctx, "INSERT INTO message(from_, to_, contents, time) VALUES(?,?,?,unixepoch('now'))",
				a.ID, msgin.To, msgin.Contents)
			if err != nil {
				wsErr(c, "error saving message")
				continue
			}

			if msgid, err := row.LastInsertId(); err != nil {
				wsErr(c, "error attaching attachments")
			} else {
				for _, fileurl := range msgin.Attachments {
					if _, err = tx.ExecContext(ctx, "INSERT INTO message_attachment(message, file) SELECT ?, id FROM file WHERE url=?", msgid, fileurl); err != nil {
						fmt.Println(err)
						wsErr(c, "could not attach one of the attachments")
						continue
					}
				}
			}

			if err := tx.Commit(); err != nil {
				wsErr(c, "could not send message")
				continue
			}
			c.WriteMessage(websocket.TextMessage, []byte("k"))

			conn, ok := conns[msgin.To]
			if ok {
				var msgout struct {
					From        int
					Username    string
					Contents    string
					Attachments []attachment
				}

				err = db.QueryRow("SELECT name FROM user WHERE id=?", a.ID).Scan(&msgout.Username)
				if err != nil {
					wsErr(c, "error getting message username")
				}
				msgout.From = a.ID
				msgout.Contents = msgin.Contents
				for _, fileurl := range msgin.Attachments {
					at := attachment{}
					at.URL = fileurl
					if err := db.QueryRow("SELECT type FROM file WHERE url=?", fileurl).Scan(&at.Type); err != nil {
						wsErr(c, "could not determine attachment type")
						continue
					}
					msgout.Attachments = append(msgout.Attachments, at)
				}
				msg, err := json.Marshal(msgout)
				if err != nil {
					wsErr(c, "error sending message")
					continue
				}
				_ = conn.WriteMessage(websocket.TextMessage, msg)
			}
		}
	})

	lounge := make(map[int]player)
	mux.HandleFunc("/loungesock/", func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()

		a, err := sockauth(c, db)
		if err != nil {
			wsErr(c, err.Error())
			return
		}

		notify := func(msgstruct any) {
			for id, user := range lounge {
				if id == a.ID { //don't notify sender
					continue
				}
				msg, err := json.Marshal(msgstruct)
				if err != nil {
					continue
				}
				//fmt.Println(string(msg))
				_ = user.c.WriteMessage(websocket.TextMessage, msg)
			}
		}

		joinInfo := struct {
			T    int
			ID   int
			Name string
		}{2, a.ID, ""}
		err = db.QueryRow("SELECT name FROM user WHERE id=?", a.ID).Scan(&joinInfo.Name)
		if err != nil {
			wsErr(c, "could not get username")
			return
		}
		notify(joinInfo)

		loungedata := struct {
			T    int
			Name string
			Us   map[int]player
		}{0, joinInfo.Name, lounge}
		msg, err := json.Marshal(loungedata)
		if err != nil {
			wsErr(c, "could not get player data")
			return
		}

		err = c.WriteMessage(websocket.TextMessage, msg)
		if err != nil {
			wsErr(c, "could not send player data")
			return
		}

		loungemx.Lock()
		lounge[a.ID] = player{c, 0, 0, joinInfo.Name}
		loungemx.Unlock()

		defer func() {
			leaveInfo := struct {
				T  int
				ID int
			}{3, a.ID}
			notify(leaveInfo)
			delete(lounge, a.ID)
		}()

		for {
			var msgin struct {
				T   int
				X   int
				Y   int
				Msg string
			}

			t, msg, err := c.ReadMessage()
			if err != nil {
				wsErr(c, "error reading message")
				break
			}
			if t == websocket.CloseMessage {
				break
			}

			err = json.Unmarshal(msg, &msgin)
			if err != nil {
				wsErr(c, "error reading message")
				continue
			}

			//fmt.Println(msgin)
			switch msgin.T {
			case 1: //move
				move := struct {
					T  int
					ID int
					X  int
					Y  int
				}{1, a.ID, msgin.X, msgin.Y}
				if p, ok := lounge[a.ID]; ok {
					loungemx.Lock()
					lounge[a.ID] = player{c, msgin.X, msgin.Y, p.Name}
					loungemx.Unlock()
				}
				notify(move)
			case 4: //chatmsg
				msg := struct {
					T        int
					ID       int
					Contents string
				}{4, a.ID, msgin.Msg}
				notify(msg)
			}
		}
	})

	mux.HandleFunc("POST /chats/", handle(func(w http.ResponseWriter, r *http.Request) error {
		var b struct {
			Auth
			Page int
		}
		err := json.NewDecoder(r.Body).Decode(&b)
		if err != nil {
			return jErr
		}
		ok := auth(db, b)
		if !ok {
			return aErr
		}

		rows, err := db.Query(`
SELECT msg.id, name, contents, time
FROM (SELECT to_ as id, time, contents FROM message WHERE from_=?
	UNION
	SELECT from_ as id, time, contents FROM message WHERE to_=?) as msg
JOIN user ON user.id = msg.id
GROUP BY msg.id
HAVING msg.time=max(msg.time)
ORDER BY msg.time DESC
LIMIT 20 OFFSET ?`, b.ID, b.ID, b.Page*20)
		if err != nil {
			fmt.Println(err)
			return e("could not get chats")
		}
		defer rows.Close()

		var chats struct {
			Count int
			Cs    []chat
		}

		for rows.Next() {
			c := chat{}
			if err := rows.Scan(&c.ID, &c.Name, &c.Contents, &c.Time); err != nil {
				return e("error reading messages")
			}
			chats.Cs = append(chats.Cs, c)
			chats.Count++
		}

		j, err := json.Marshal(chats)
		if err != nil {
			return e("error sending chats")
		}
		fmt.Fprintf(w, string(j))

		return nil
	}))

	mux.HandleFunc("POST /search/", handle(func(w http.ResponseWriter, r *http.Request) error {
		var b struct {
			Auth
			Query string
			Page  int
		}
		err := json.NewDecoder(r.Body).Decode(&b)
		if err != nil {
			return jErr
		}
		ok := auth(db, b)
		if !ok {
			return aErr
		}

		if !alphanum(b.Query) {
			return e("query should be alphanumeric")
		}

		var results struct {
			Count int
			Rs    []userData
		}
		rows, err := db.Query("SELECT id, name, status FROM user WHERE name LIKE ? LIMIT 20 OFFSET ?", "%"+b.Query+"%", b.Page*20)
		if err != nil {
			return e("could not get users")
		}
		for rows.Next() {
			r := userData{}
			if err := rows.Scan(&r.ID, &r.Name, &r.Status); err != nil {
				return e("error reading user data")
			}
			results.Rs = append(results.Rs, r)
			results.Count++
		}

		j, err := json.Marshal(results)
		if err != nil {
			return e("error sending data")
		}

		fmt.Fprintf(w, string(j))
		return nil
	}))

	mux.HandleFunc("POST /upload/", handle(func(w http.ResponseWriter, r *http.Request) error {
		r.Body = http.MaxBytesReader(w, r.Body, 1024*1024*10)
		err := r.ParseMultipartForm(1024 * 1024 * 10)
		if err != nil {
			var maxBytesError *http.MaxBytesError
			if errors.As(err, &maxBytesError) {
				return e("uploads are limited to 10mb")
			}
			return e("error reading request")
		}

		var a Auth
		authstr := r.PostFormValue("auth")
		if err := json.Unmarshal([]byte(authstr), &a); err != nil {
			return jErr
		}

		file, handler, err := r.FormFile("file")
		if err != nil {
			return e("error getting file")
		}
		defer file.Close()

		contentType := handler.Header.Get("Content-Type")
		types := map[string]int{
			"image/jpeg":       1,
			"image/png":        1,
			"image/webp":       1,
			"image/gif":        1,
			"video/mp4":        2,
			"video/webm":       2,
			"video/x-matroska": 2,
			"audio/mpeg":       3,
			"audio/flac":       3,
			"audio/x-m4a":      3,
			"audio/aac":        3,
			"audio/wav":        3,
		}
		t, ok := types[contentType]
		if !ok {
			fmt.Println(contentType)
			t = 0 //unknown
		}

		url, err := randStr(64)
		if err != nil {
			return e("error generating file url")
		}
		dst, err := os.Create("./static/files/" + url)
		if err != nil {
			return e("error opening location to save file")
		}
		defer dst.Close()

		if _, err := io.Copy(dst, file); err != nil {
			return e("error uploading file")
		}

		_, err = db.Exec("INSERT INTO file(owner, url, name, type, time, public) VALUES(?,?,?,?,unixepoch('now'),0)", a.ID, url, handler.Filename, t)
		if err != nil {
			fmt.Println(err)
			return e("error saving file info")
		}

		return nil
	}))

	mux.HandleFunc("POST /files/", handle(func(w http.ResponseWriter, r *http.Request) error {
		var b struct {
			Auth
			Page  int
			Query string
		}
		err := json.NewDecoder(r.Body).Decode(&b)
		if err != nil {
			return jErr
		}
		ok := auth(db, b)
		if !ok {
			return aErr
		}

		b.Query = strings.ReplaceAll(b.Query, "%", "\\%")
		b.Query = strings.ReplaceAll(b.Query, "_", "\\_")
		rows, err := db.Query("SELECT id, name, url, type FROM file WHERE owner = ? AND name LIKE ? ESCAPE '\\' ORDER BY id DESC LIMIT 20 OFFSET ?", b.ID, "%"+b.Query+"%", b.Page*20)
		if err != nil {
			return e("could not get files")
		}

		var files struct {
			Count int
			Fs    []fileInfo
		}

		for rows.Next() {
			f := fileInfo{}
			if err := rows.Scan(&f.ID, &f.Name, &f.URL, &f.Type); err != nil {
				return e("error scanning files")
			}
			files.Fs = append(files.Fs, f)
			files.Count++
		}

		j, err := json.Marshal(files)
		if err != nil {
			return e("could not send files")
		}

		fmt.Fprintf(w, string(j))
		return nil
	}))

	mux.HandleFunc("POST /feedback/", handle(func(w http.ResponseWriter, r *http.Request) error {
		var b struct {
			Auth
			Contents string
			Type     int
		}
		err := json.NewDecoder(r.Body).Decode(&b)
		if err != nil {
			fmt.Println(err)
			return jErr
		}
		ok := auth(db, b)
		if !ok {
			return aErr
		}

		if t := b.Type; t < 1 || t > 3 {
			return e("feedback type should be between 1 and 3")
		}

		if l := len(b.Contents); l < 10 || l > 2048 {
			return e("feedback text length should be between 10 and 2048 characters")
		}

		_, err = db.Exec("INSERT INTO feedback(user, contents, type, time) values(?,?,?,unixepoch('now'))", b.ID, b.Contents, b.Type)
		if err != nil {
			return e("error leaving feedback")
		}
		return nil
	}))

	mux.HandleFunc("POST /tag/", handle(func(w http.ResponseWriter, r *http.Request) error {
		var b struct {
			Auth
			Tag  string
			Page int
		}
		err := json.NewDecoder(r.Body).Decode(&b)
		if err != nil {
			return jErr
		}
		ok := auth(db, b)
		if !ok {
			return aErr
		}

		rows, err := db.Query("SELECT post.id, post.contents, post.time, post.parent_post_id, count(child.id), user.name, post.user_id FROM post_tag JOIN post ON post_tag.post=post.id JOIN tag ON post_tag.tag=tag.id LEFT JOIN post AS child ON post.id = child.parent_post_id JOIN user ON post.user_id=user.id WHERE tag.name=? GROUP BY post.id ORDER BY post.time DESC LIMIT 20 OFFSET ?", b.Tag, b.Page*20)
		if err != nil {
			return e("error getting posts")
		}
		defer rows.Close()

		j, err := scanPosts(db, rows)
		if err != nil {
			return err
		}
		w.Write(j)

		return nil
	}))

	mux.HandleFunc("POST /tags/", handle(func(w http.ResponseWriter, r *http.Request) error {
		var b struct {
			Auth
			Page  int
			Query string
		}
		err := json.NewDecoder(r.Body).Decode(&b)
		if err != nil {
			return jErr
		}
		ok := auth(db, b)
		if !ok {
			return aErr
		}

		var tags struct {
			Count int
			Ts    []taginfo
		}

		b.Query = strings.ReplaceAll(b.Query, "%", "\\%")
		b.Query = strings.ReplaceAll(b.Query, "_", "\\_")
		rows, err := db.Query("SELECT name, count(tag.id) as c FROM post_tag JOIN tag ON post_tag.tag=tag.ID WHERE name LIKE ? ESCAPE '\\' GROUP BY tag.id ORDER BY c DESC LIMIT 20 OFFSET ?", "%"+b.Query+"%", b.Page*20)
		if err != nil {
			fmt.Println(err)
			return e("could not get hashtag info")
		}
		defer rows.Close()

		for rows.Next() {
			t := taginfo{}
			if err := rows.Scan(&t.Name, &t.Posts); err != nil {
				return e("couold not scan tag info")
			}
			tags.Ts = append(tags.Ts, t)
		}
		tags.Count = len(tags.Ts)

		j, err := json.Marshal(tags)
		if err != nil {
			return e("error sending tag info")
		}

		w.Write(j)
		return nil
	}))

	mux.HandleFunc("POST /testauth/", handle(func(w http.ResponseWriter, r *http.Request) error {
		var a Auth
		err := json.NewDecoder(r.Body).Decode(&a)
		if err != nil {
			return jErr
		}
		ok := auth(db, a)
		if !ok {
			return aErr
		}
		return nil
	}))

	server := &http.Server{
		Handler:      cors(db, mux),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	mux.Handle("/", http.FileServer(http.Dir("static")))

	global := func() {
		server.Addr = ":443"
		tls := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache("certs"),
			HostPolicy: autocert.HostWhitelist("minimint.xyz", "www.minimint.xyz"),
			Email:      "tezul@yahoo.com",
		}
		server.TLSConfig = tls.TLSConfig()

		go func() {
			h := tls.HTTPHandler(nil)
			//If fallback is nil, the returned handler redirects all
			//GET and HEAD requests to the default TLS port 443 with 302 Found status code
			log.Fatal(http.ListenAndServe(":80", h))
		}()
		log.Fatal(server.ListenAndServeTLS("", ""))
	}

	local := func() {
		server.Addr = ":3000"
		log.Fatal(server.ListenAndServeTLS("127.0.0.1.pem", "127.0.0.1-key.pem"))
	}

	if len(os.Args) < 2 {
		fmt.Println("global or local?")
	} else if os.Args[1] == "global" {
		global()
	} else if os.Args[1] == "local" {
		local()
	} else {
		fmt.Println("invalid mode")
	}
}
