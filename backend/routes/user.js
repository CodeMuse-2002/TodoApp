const express = require('express')
const db = require('../db')
const utils = require('../utils')
const crypto = require('crypto-js')
const jwt = require('jsonwebtoken')
const config = require('../config')

const router = express.Router()

router.post('/register', (request, response) => {
  const { fname, email, phone, password, lname } = request.body

  const statement = `
    INSERT INTO User (
        fname, lname, email, password, phone
    ) VALUES (?, ?, ?, ?, ?)
  `

  // encrypt the password
  const encryptedPassword = String(crypto.MD5(password))

  db.pool.execute(
    statement,
    [fname, lname, email, encryptedPassword, phone],
    (error, result) => {
      if (!error) {
        response.send(utils.createResult(error, result))
      } else {
        response.send(utils.createError(error))
      }
    }
  )
})

router.post('/login', (request, response) => {
  const { email, password } = request.body

  const statement = `
    SELECT id, fname, lname, phone, isActive 
    FROM user
    WHERE email = ? AND password = ?
  `

  // encrypt the password
  const encryptedPassword = String(crypto.MD5(password))

  db.pool.query(statement, [email, encryptedPassword], (error, users) => {
    // if error exists
    if (error) {
      response.send(utils.createError(error))
    } else {
      // query got successfully executed

      // check if user exists
      if (users.length == 0) {
        // user does not exist
        response.send(utils.createError('user does not exist'))
      } else {
        // at least one user exists
        // send the users data to the client

        const { id, fname, lname, phone, isActive } = users[0]

        // check if the user is active
        if (isActive) {
          // create a payload
          const payload = { id, fname, lname, email }

          // create a token
          const token = jwt.sign(payload, config.secrete)

          response.send(
            utils.createSuccess({
              token,
              fname,
              lname,
              phone,
            })
          )
        } else {
          // user is not active
          response.send(
            utils.createError(
              'You can not login as your account is not active. Please contact administrator.'
            )
          )
        }
      }
    }
  })
})

router.put('/profile', (request, response) => {
  const { fname, lname, phone } = request.body
  const statement = `
    UPDATE user
    SET fname = ?, lname = ?, phone = ?
    WHERE id = ?
  `
  db.pool.execute(
    statement,
    [fname, lname, phone, request.user['id']],
    (error, result) => {
      response.send(utils.createResult(error, result))
    }
  )
})

router.put('/update-password', (request, response) => {
  const { password } = request.body

  // encrypt the password
  const encryptedPassword = String(crypto.MD5(password))

  const statement = `
    UPDATE user
    SET password = ?
    WHERE id = ?
  `
  db.pool.execute(
    statement,
    [encryptedPassword, request.user['id']],
    (error, result) => {
      response.send(utils.createResult(error, result))
    }
  )
})

router.get('/profile', (request, response) => {
  const statement = `
    SELECT fname, lname, email, phone
    FROM user
    WHERE id = ?
  `
  db.pool.query(statement, [request.user['id']], (error, users) => {
    if (error) {
      response.send(utils.createError(error))
    } else {
      if (users.length == 0) {
        response.send(utils.createError('user does not exist'))
      } else {
        response.send(utils.createSuccess(users[0]))
      }
    }
  })
})

router.get('/all-users', (request, response) => {
  const statement = `
    SELECT id, fname, lname, email, phone, isActive
    FROM user
  `
  db.pool.query(statement, (error, users) => {
    response.send(utils.createResult(error, users))
  })
})

router.patch('/make-active/:id', (request, response) => {
  const { id } = request.params

  const statement = `
    UPDATE user
    SET isActive = 1
    WHERE id = ?
  `
  db.pool.query(statement, [id], (error, items) => {
    response.send(utils.createResult(error, items))
  })
})

router.patch('/make-inactive/:id', (request, response) => {
  const { id } = request.params

  const statement = `
    UPDATE user
    SET isActive = 0
    WHERE id = ?
  `
  db.pool.query(statement, [id], (error, items) => {
    response.send(utils.createResult(error, items))
  })
})

module.exports = router
