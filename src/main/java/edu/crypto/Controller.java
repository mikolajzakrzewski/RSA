package edu.crypto;

import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.control.TextArea;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;


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

    private final Converter converter = new Converter();

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

    public void generateButtonClick() {
        this.rsa.generateKeys();
        nPublicKey.setText(rsa.getN().toString(16));
        ePublicKey.setText(rsa.getE().toString(16));
        dPrivateKey.setText(rsa.getD().toString(16));
    }

    public void encryptButtonClick() {
        BigInteger n = new BigInteger(this.nPublicKey.getText(), 16);
        BigInteger e = new BigInteger(this.ePublicKey.getText(), 16);
        String stringText = decryptedTextArea.getText();
        byte[] byteText = stringText.getBytes();
        ArrayList<BigInteger> bigIntegerArrayListCypheredText = rsa.cypherText(byteText, e, n);
        encryptedTextArea.setText(converter.bigIntegerArrayListToHexString(bigIntegerArrayListCypheredText));
    }

    public void decryptButtonClick() {
        BigInteger n = new BigInteger(this.nPublicKey.getText(), 16);
        BigInteger d = new BigInteger(this.dPrivateKey.getText(), 16);
        String stringText = encryptedTextArea.getText();
        ArrayList<BigInteger> bigIntegerArrayListText = converter.hexStringToBigIntegerArrayList(stringText);
        byte[] decryptedText = rsa.decipherText(bigIntegerArrayListText, d, n);
        decryptedTextArea.setText(new String(decryptedText, StandardCharsets.UTF_8));
    }

    private void noFileSelectedWarning() {
        Alert alert = new Alert(Alert.AlertType.WARNING);
        alert.setTitle("Warning");
        alert.setHeaderText(null);
        alert.setContentText("Plik nie został wybrany");
        alert.showAndWait();
    }

    public void encryptFileButtonClick() throws IOException {
        if (decodedInputFile == null || encodedOutputFile == null) {
            noFileSelectedWarning();
            return;
        }
        BigInteger n = new BigInteger(this.nPublicKey.getText(), 16);
        BigInteger e = new BigInteger(this.ePublicKey.getText(), 16);
        byte[] message = Files.readAllBytes(Paths.get(decodedInputFile.toURI()));
        ArrayList<BigInteger> bigIntegerArrayListCypheredMessage = rsa.cypherText(message, e, n);
        String hexStringCypheredMessage = converter.bigIntegerArrayListToHexString(bigIntegerArrayListCypheredMessage);
        try (BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(encodedOutputFile))) {
            bufferedWriter.write(hexStringCypheredMessage);
        }
    }

    public void decryptFileButtonClick() throws IOException {
        if (decodedInputFile == null || encodedOutputFile == null) {
            noFileSelectedWarning();
            return;
        }
        BigInteger n = new BigInteger(this.nPublicKey.getText(), 16);
        BigInteger d = new BigInteger(this.dPrivateKey.getText(), 16);
        StringBuilder fileContentBuilder = new StringBuilder();
        try (BufferedReader bufferedReader = new BufferedReader(new FileReader(encodedInputFile))) {
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                fileContentBuilder.append(line);
            }
        }
        String cipheredMessageHex = fileContentBuilder.toString();
        ArrayList<BigInteger> bigIntegerArrayListCipheredMessage = converter.hexStringToBigIntegerArrayList(cipheredMessageHex);
        byte[] byteDecryptedFile = rsa.decipherText(bigIntegerArrayListCipheredMessage, d, n);
        Files.write(decodedOutputFile.toPath(), byteDecryptedFile);
    }

    public void encodedInputFileButtonClick() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setInitialDirectory(new File(System.getProperty("user.dir")));
        fileChooser.setTitle("Wybierz zaszyfrowany plik");
        Stage stage = new Stage();
        encodedInputFile = fileChooser.showOpenDialog(stage);
        if (encodedInputFile != null) {
            chosenInputEncodedFile.setText(encodedInputFile.toString());
        }
    }

    public void decodedInputFileButtonClick() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setInitialDirectory(new File(System.getProperty("user.dir")));
        fileChooser.setTitle("Wybierz jawny plik");
        Stage stage = new Stage();
        decodedInputFile = fileChooser.showOpenDialog(stage);
        if(decodedInputFile != null) {
            chosenInputDecodedFile.setText(decodedInputFile.toString());
        }
    }

    private File chooseFile() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setInitialDirectory(new File(System.getProperty("user.dir")));
        fileChooser.setTitle("Wybierz plik do zapisu");
        Stage stage = new Stage();
        return fileChooser.showSaveDialog(stage);
    }

    public void decodedOutputFileButtonClick() {
        decodedOutputFile = chooseFile();
        if(decodedOutputFile != null) {
            chosenOutputDecodedFile.setText(decodedOutputFile.toString());
        }
    }

    public void encodedOutputFileButtonClick() {
        encodedOutputFile = chooseFile();
        if(encodedOutputFile != null) {
            chosenOutputEncodedFile.setText(encodedOutputFile.toString());
        }
    }
}
