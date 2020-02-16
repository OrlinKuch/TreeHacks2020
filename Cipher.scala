object Cipher{
  /** Bit-wise exclusive-or of two characters */
  def xor(a: Char, b: Char) : Char = (a.toInt ^ b.toInt).toChar

  /** Print ciphertext in octal */
  def showCipher(cipher: Array[Char]) =
    for(c <- cipher){ print(c/64); print(c%64/8); print(c%8); print(" ") }

  /** Read file into array */
  def readFile(fname: String) : Array[Char] =
    scala.io.Source.fromFile(fname).toArray

  /** Read from stdin in a similar manner */
  def readStdin() = scala.io.Source.stdin.toArray

  /** Encrypt plain using key; can also be used for decryption */
  def encrypt(key: Array[Char], plain: Array[Char]) : Array[Char] = {
    val n=plain.size
    val m=key.size
    var cipher = new Array[Char](n)
    var i=0
    while(i<n){
      cipher(i)=xor(plain(i),key(i%m))
      i+=1
    }
    cipher
  }

  /** Try to decrypt ciphertext, using crib as a crib */
  def tryCrib(crib: Array[Char], ciphertext: Array[Char]) : Unit = {
    val n=ciphertext.size
    val m=crib.size
    val keyChars = new Array[Char](m)
    var i=0 //start
    var k=0
    var done:Boolean=false
    var l=0
    while(i+m<n && !done){
      k=0
      while(k<m) {
        keyChars(k) = xor(ciphertext(i+k), crib(k))
        k += 1
      }
      l=recu(new String(keyChars)) //j
      if(l<=m-2) done=true
      else i+=1
    }
    if(i!=n-m){
      var realBegin = l-i%l
      var finalKeyChars = new Array[Char](l)
      finalKeyChars(0)=keyChars(l-1)
      var q = 0
      while(q+realBegin<l){
        finalKeyChars(q)=keyChars(realBegin+q)
        q+=1
      }
      while(q<l){
        finalKeyChars(q)=keyChars(realBegin+q-l)
        q+=1
      }
      var p=0
      while(p<l){
        print(finalKeyChars(p))
        p+=1
      }
      println
      var r=0
      while(r<n){
        print(xor(finalKeyChars(r%l),ciphertext(r)))
        r+=1
      }
    }
    else println("Couldn't find cipher!")
  }

  /** Finds the smallest number j such that keyChars[0..K-j) = keyChars[j..K) */
  def recu(a: String) : Int = {
    val N = a.length
    var n=1
    var x: Boolean=false
    while(n<N && x==false){
      var k=0
      x=true
      while(k<N-n && x==true){
        if(a(k)!=a(k+n)) x=false
        k+=1
      }
      if(x==false) n+=1
    }
    n
  }

  /** The first statistical test, to guess the length of the key */
  def crackKeyLen(ciphertext: Array[Char]) : Unit = {
    val a = ciphertext.size
    var shift = 1
    while(shift<30){
      var i=0
      var cntr=0
      while(shift+i<a){
        if(ciphertext(i)==ciphertext(shift+i)) cntr+=1
        i+=1
      }
      println(shift + ": " + cntr)
      shift+=1
    }
  }

  /** The second statistical test, to guess characters of the key. */
  def crackKey(klen: Int, ciphertext: Array[Char]) : Unit = {
    var b=1
    val a=ciphertext.size
    while(klen*b<a){
      var c=klen*b
      var i=0
      while(c+i<a){
        if(ciphertext(i)==ciphertext(c+i)){
          var d = xor(ciphertext(i),' ')
          if(d.toInt<=127 && d.toInt>=32) println(i%klen + " " + d)
        }
        i+=1
      }
      b+=1
    }
  }

  /** The main method just selects which piece of functionality to run */
  def main(args: Array[String]) = {
    // string to print if error occurs
    val errString =
      "Usage: scala Cipher (-encrypt|-decrypt) key [file]\n"+
        "     | scala Cipher -crib crib [file]\n"+
        "     | scala Cipher -crackKeyLen [file]\n"+
        "     | scala Cipher -crackKey len [file]"

    // Get the plaintext, either from the file whose name appears in position
    // pos, or from standard input
    def getPlain(pos: Int) =
      if(args.length==pos+1) readFile(args(pos)) else readStdin

    // Check there are at least n arguments
    def checkNumArgs(n: Int) = if(args.length<n){println(errString); sys.exit}

    // Parse the arguments, and call the appropriate function
    checkNumArgs(1)
    val command = args(0)
    if(command == "-encrypt" || command == "-decrypt"){
      checkNumArgs(2); val key = args(1).toArray; val plain = getPlain(2)
      print(new String (encrypt(key,plain)))
    }
    else if(command == "-crib"){
      checkNumArgs(2); val key = args(1).toArray; val plain = getPlain(2)
      tryCrib(key, plain)
    }
    else if(command == "-crackKeyLen"){
      checkNumArgs(1); val plain = getPlain(1)
      crackKeyLen(plain)
    }
    else if(command == "-crackKey"){
      checkNumArgs(2); val klen = args(1).toInt; val plain = getPlain(2)
      crackKey(klen, plain)
    }
    else println(errString)
  }
}
