// For more information about this file see https://dove.feathersjs.com/guides/cli/service.test.html
const axios = require('axios')
const url = require('url')
import assert from 'assert'
import { app } from '../../../src/app.js'

const port = app.get('port') || 8998
const getUrl = (pathname) =>
  url.format({
    hostname: app.get('host') || 'localhost',
    protocol: 'http',
    port,
    pathname
  })

describe("'users' service", () => {
  it('registered the service', () => {
    const service = app.service('users')
    assert.ok(service, 'Registered the service')
  })
})

describe('Additional security checks on user endpoints', () => {
  let alice = {
    email: 'alice@feathersjs.com',
    password: 'supersecret12'
  }

  let bob = {
    email: 'bob@feathersjs.com',
    password: 'supersecret1'
  }

  const getTokenForUser = async (user) => {
    const { accessToken } = await app.service('authentication').create({
      strategy: 'local',
      ...user
    })
    return accessToken
  }

  const setupUser = async (user) => {
    const { _id } = await app.service('users').create(user)
    user._id = _id
    user.accessToken = await getTokenForUser(user)
  }

  let server

  before(async () => {
    await setupUser(alice)
    await setupUser(bob)

    server = app.listen(port)
  })

  after(async () => {
    server.close()
  })

  it('should return 403 when user tries to delete another user', async () => {
    const { accessToken } = alice
    const { _id: targetId } = bob
    const config = { headers: { Authorization: `Bearer ${accessToken}` } }

    try {
      await axios.delete(getUrl(`/users/${targetId}`), config)
    } catch (error) {
      const { response } = error

      assert.equal(response.status, 403)
      assert.equal(response.data.message, 'You are not authorized to perform this operation on another user')
    }
  })

  it('should return 403 when user tries to put another user', async () => {
    try {
      const { accessToken } = bob
      const { _id: targetId } = alice
      const config = { headers: { Authorization: `Bearer ${accessToken}` } }
      const testData = { password: bob.password }

      await axios.put(getUrl(`/users/${targetId}`), testData, config)
    } catch (error) {
      const { response } = error

      assert.equal(response.status, 403)
      assert.equal(response.data.message, 'You are not authorized to perform this operation on another user')
    }
  })

  it('should return 403 when user tries to patch another user', async () => {
    try {
      const { accessToken } = alice
      const { _id: targetId } = bob
      const config = { headers: { Authorization: `Bearer ${accessToken}` } }
      const testData = { password: alice.password }

      await axios.patch(getUrl(`/users/${targetId}`), testData, config)
    } catch (error) {
      const { response } = error

      assert.equal(response.status, 403)
      assert.equal(response.data.message, 'You are not authorized to perform this operation on another user')
    }
  })
})
