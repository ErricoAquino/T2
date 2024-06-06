import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

// Nel costruttore o come variabile statica della classe UserDao
private static final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

// Quando si salva un nuovo utente nel database
public void saveUser(UserBean user) throws SQLException {
    Connection connection = null;
    PreparedStatement preparedStatement = null;

    String insertSQL = "INSERT INTO users (username, password) VALUES (?, ?)";
    try {
        connection = ds.getConnection();
        preparedStatement = connection.prepareStatement(insertSQL);
        preparedStatement.setString(1, user.getUsername());
        preparedStatement.setString(2, passwordEncoder.encode(user.getPassword()));
        preparedStatement.executeUpdate();
    } finally {
        if (preparedStatement != null) preparedStatement.close();
        if (connection != null) connection.close();
    }
}

// Quando si recupera un utente dal database per il login
public UserBean doRetrieve(String username, String password) throws SQLException {
    Connection connection = null;
    PreparedStatement preparedStatement = null;
    UserBean user = null;

    String selectSQL = "SELECT * FROM users WHERE username = ?";
    try {
        connection = ds.getConnection();
        preparedStatement = connection.prepareStatement(selectSQL);
        preparedStatement.setString(1, username);
        ResultSet rs = preparedStatement.executeQuery();

        if (rs.next()) {
            String hashedPassword = rs.getString("password");
            if (passwordEncoder.matches(password, hashedPassword)) {
                user = new UserBean();
                user.setUsername(username);
                user.setPassword(hashedPassword); // Puoi impostare l'hash come password nel bean, o lasciarla vuota per motivi di sicurezza
                user.setValid(true);
            }
        }
    } finally {
        if (preparedStatement != null) preparedStatement.close();
        if (connection != null) connection.close();
    }
    return user;
}
