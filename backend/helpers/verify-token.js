const jwt = require('jsonwebtoken')
const getToken = require('./get-token')

//middleware to validate token
const checkToken = (req, res, next) => {

    if(!req.headers.authorization) {
        return res.status(401).json({messange: 'Acesso negado!'})
    }

    const token = getToken(req)

    if(!token) {
        return res.status(401).json({messange: 'Acesso negado!'})
    }

    try{
        const verifed = jwt.verify(token, "nossosecret")
        req.user = verifed
        next()
    }catch (err) {
        return res.status(400).json({messange: 'Token inválido!'})
    }
}

module.exports = checkToken