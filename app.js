//MODULES
const express      = require('express'),
      exphbs       = require('express-handlebars'),
      mongoose     = require('mongoose'),
      passport     = require('passport'),
      session      = require('express-session'),
      bodyParser   = require('body-parser'),
      cookieParser = require('cookie-parser'),
      flash        = require('connect-flash')

const app = express()

//BD
mongoose.connect('mongodb://localhost:27017/test', {
    useUnifiedTopology: true,
    useNewUrlParser: true,
    useCreateIndex: true
});

//MORE CONFIGS
app.use(flash());
app.use(bodyParser.urlencoded({extended: true}))
app.use(bodyParser.json())
const path = require('path');
app.use(express.static(path.join(__dirname,'public')))
app.engine('handlebars', exphbs())
app.set('view engine', 'handlebars')
app.use(cookieParser());
app.use(bodyParser.urlencoded({extended: true}))
app.use(bodyParser.json())
app.use(session({
    secret: '44421984(%09u7*&218g1erg41fsdr8',
    resave: true,
    saveUninitialized: true
}))
app.use(passport.initialize())
app.use(passport.session())

//ROUTES
const panel = require('./routes/panel'),
      auth  = require('./routes/auth')
app.use('/panel', panel)
app.use('/auth', auth)

//VIEWS
app.get('/', (req, res) => {
    res.render('home')
})

const port = process.env.PORT || 21068
app.listen(port, () => {
    console.log(`conectado na porta ${port}`)
})