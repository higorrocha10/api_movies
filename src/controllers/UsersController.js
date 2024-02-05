const { hash, compare } = require("bcryptjs") // hash es la función que genera el cifrado.
const AppError = require("../utils/AppError")
const sqliteConnection = require("../database/sqlite")

class UsersController {
  async create(request, response) {
    const { name, email, password } = request.body

    const database = await sqliteConnection()
    const checkUserExists = await database.get(
      "SELECT * FROM users WHERE email = (?)",
      [email]
    )

    if (checkUserExists) {
      throw new AppError("Este e-mail ya está en uso.")
    }

    const hashedPassword = await hash(password, 8)

    // Insertando / Guardando usuarios en el banco de datos.
    await database.run(
      "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
      [name, email, hashedPassword]
    )

    return response.status(201).json()
  }

  async update(request, response) {
    const { name, email, password, old_password } = request.body
    const { id } = request.params

    const database = await sqliteConnection()
    const user = await database.get("SELECT * FROM users WHERE id = (?)", [id])

    // console.log(user)

    if (!user) {
      throw new AppError("Usuario no encontrado.")
    }

    const userWithUpdatedEmail = await database.get(
      "SELECT * FROM users WHERE email = (?)",
      [email]
    )

    if (userWithUpdatedEmail && userWithUpdatedEmail.id !== user.id) {
      throw new AppError("Este e-mail ya está registrado.")
    }

    user.name = name ?? user.name
    user.email = email ?? user.email

    if (password && !old_password) {
      throw new AppError("Tienes que informar la clave antigua.")
    }

    if (password && old_password) {
      const checkOldPassword = await compare(old_password, user.password)

      if (!checkOldPassword) {
        throw new AppError("Las contraseñas no coinciden.")
      }

      user.password = await hash(password, 8)
    }

    await database.run(
      `
      UPDATE users SET
      name = ?,
      email = ?,
      password = ?,
      updated_at = DATETIME('now') 
      WHERE id = ?`,
      [user.name, user.email, user.password, id]
    )

    //DATETIME('now): Función del banco de datos.

    return response.json()
  }
}

module.exports = UsersController
