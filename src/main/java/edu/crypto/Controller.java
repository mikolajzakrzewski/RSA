package edu.crypto;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.control.TextArea;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;


public class Controller {

    @FXML
    private TextField nPublicKey;

    @FXML
    private TextField ePublicKey;

    @FXML
    private TextField dPrivateKey;

    @FXML
    private TextArea decryptedTextArea;

    @FXML
    private TextArea encryptedTextArea;

    @FXML
    private Label chosenInputDecodedFile;

    @FXML
    private Label chosenInputEncodedFile;

    @FXML
    private Label chosenOutputDecodedFile;

    @FXML
    private Label chosenOutputEncodedFile;

    private final RSA rsa = new RSA();

    private File encodedInputFile;

    private File decodedInputFile;

    private File encodedOutputFile;

    private File decodedOutputFile;

    public void initialize() {
        this.rsa.generateKeys();
        nPublicKey.setText(rsa.getN().toString(16));
        ePublicKey.setText(rsa.getE().toString(16));
        dPrivateKey.setText(rsa.getD().toString(16));
    }

    public void generateButtonClick(ActionEvent actionEvent) {
        this.rsa.generateKeys();
        nPublicKey.setText(rsa.getN().toString(16));
        ePublicKey.setText(rsa.getE().toString(16));
        dPrivateKey.setText(rsa.getD().toString(16));
    }

    public void encryptButtonClick(ActionEvent actionEvent) {
        BigInteger n = new BigInteger(this.nPublicKey.getText(), 16);
        BigInteger e = new BigInteger(this.ePublicKey.getText(), 16);
        byte[] byteDecryptedMessage = decryptedTextArea.getText().getBytes();
        String stringEncryptedMessage = rsa.cypherText(byteDecryptedMessage, e, n).toString();
        encryptedTextArea.setText(stringEncryptedMessage);
    }

    public void decryptButtonClick(ActionEvent actionEvent) {
        BigInteger n = new BigInteger(this.nPublicKey.getText(), 16);
        BigInteger d = new BigInteger(this.dPrivateKey.getText(), 16);
        byte[] byteEncryptedMessage = new BigInteger(encryptedTextArea.getText()).toByteArray();
        String decryptedText = new String(rsa.decipherText(byteEncryptedMessage, d, n).toByteArray(), StandardCharsets.UTF_8);
        decryptedTextArea.setText(decryptedText);
    }

    public void encryptFileButtonClick(ActionEvent actionEvent) throws IOException {
        if (decodedInputFile == null || encodedOutputFile == null)  {
            Alert alert = new Alert(Alert.AlertType.WARNING);
            alert.setTitle("Warning");
            alert.setHeaderText(null);
            alert.setContentText("Plik nie został wybrany");
            alert.showAndWait();
            return;
        }
        BigInteger n = new BigInteger(this.nPublicKey.getText(), 16);
        BigInteger e = new BigInteger(this.ePublicKey.getText(), 16);
        byte[] message = Files.readAllBytes(Paths.get(decodedInputFile.toURI()));
        byte[] cypheredMessage = rsa.cypherText(message, e, n).toByteArray();
        Files.write(encodedOutputFile.toPath(), cypheredMessage);
    }

    public void decryptFileButtonClick(ActionEvent actionEvent) throws IOException {
        if (encodedInputFile == null || decodedOutputFile == null)  {
            Alert alert = new Alert(Alert.AlertType.WARNING);
            alert.setTitle("Warning");
            alert.setHeaderText(null);
            alert.setContentText("Plik nie został wybrany");
            alert.showAndWait();
            return;
        }
        BigInteger n = new BigInteger(this.nPublicKey.getText(), 16);
        BigInteger d = new BigInteger(this.dPrivateKey.getText(), 16);
        byte[] byteEncryptedFile = Files.readAllBytes(Paths.get(encodedInputFile.toURI()));
        byte[] byteDecryptedFile = rsa.decipherText(byteEncryptedFile, d, n).toByteArray();
        Files.write(decodedOutputFile.toPath(), byteDecryptedFile);
    }

    public void encodedInputFileButtonClick(ActionEvent actionEvent) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setInitialDirectory(new File(System.getProperty("user.dir")));
        fileChooser.setTitle("Wybierz zaszyfrowany plik");
        FileChooser.ExtensionFilter extFilter = new FileChooser.ExtensionFilter("Text Files (*.txt)", "*.txt");
        fileChooser.getExtensionFilters().add(extFilter);
        Stage stage = new Stage();
        encodedInputFile = fileChooser.showOpenDialog(stage);
        if(encodedInputFile != null) {
            chosenInputEncodedFile.setText(encodedInputFile.toString());
        }
    }

    public void decodedInputFileButtonClick(ActionEvent actionEvent) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setInitialDirectory(new File(System.getProperty("user.dir")));
        fileChooser.setTitle("Wybierz jawny plik");
        Stage stage = new Stage();
        decodedInputFile = fileChooser.showOpenDialog(stage);
        if(decodedInputFile != null) {
            chosenInputDecodedFile.setText(decodedInputFile.toString());
        }
    }

    public void decodedOutputFileButtonClick(ActionEvent actionEvent) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setInitialDirectory(new File(System.getProperty("user.dir")));
        fileChooser.setTitle("Wybierz plik do zapisu");
        Stage stage = new Stage();
        decodedOutputFile = fileChooser.showSaveDialog(stage);
        if(decodedOutputFile != null) {
            chosenOutputDecodedFile.setText(decodedOutputFile.toString());
        }
    }

    public void encodedOutputFileButtonClick(ActionEvent actionEvent) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setInitialDirectory(new File(System.getProperty("user.dir")));
        fileChooser.setTitle("Wybierz plik do zapisu");
        FileChooser.ExtensionFilter extFilter = new FileChooser.ExtensionFilter(".txt File",".txt");
        fileChooser.getExtensionFilters().add(extFilter);
        Stage stage = new Stage();
        encodedOutputFile = fileChooser.showSaveDialog(stage);
        if(encodedOutputFile != null) {
            chosenOutputEncodedFile.setText(encodedOutputFile.toString());
        }
    }
}
