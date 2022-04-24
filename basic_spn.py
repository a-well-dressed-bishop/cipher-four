from sage.crypto.sbox import SBox
from sage.rings.integer import Integer
from sage.rings.integer_ring import ZZ
from sage.structure.sage_object import SageObject
from sage.modules.free_module_element import vector
from sage.rings.finite_rings.finite_field_constructor import GF

class cipher_four(SageObject):
    """
    An implementation of a basic SP-Network

    ATTRIBUTES
    ----------
    
    `_rounds` : int
        the number of the enc. rounds
    
    `_pbox` : list
        (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 0)
    
    `_sbox` : SBox
        (6, 4, 12, 5, 0, 7, 2, 14, 1, 15, 3, 13, 8, 10, 9, 11)
    
    `_vec_out` : bool
        Controls whether the output of encryption/decryption
        should be a vector-like binary repr. of the output integer
    
    `_round_keys` : iterable
        Mostly for testing purposes. 
        Should be an iterable of length `self._rounds + 1`.
        Each entry is an integer OR an iterable 
        binary representation of an integer.
        Any key must be in `range(0xffff + 1)`.
        If no keys are provided, a random set 
        will be generated and used.

    METHODS (the most important ones, anyway)
    -------

    cipher_four(input_, round_keys=None, alg=0):
        Applies cipher_four enc/dec on the _input

    encrypt(plaintext, round_keys=None)
        Encrypts the given `plaintext` with the `round_keys`.
        If no keys are provided, a random set 
        will be generated and used.
    
    decrypt(ciphertext, round_keys=None)
        Decrypts the give `ciphertext` with the `round_keys`.
        If no keys are provided, will check the `self._round_keys`.
        If it's `None`, raises an Exception.

    USAGE EXAMPLES
    --------------

    """
    
    def __init__(self, rounds=5, vector_output=False, round_keys=None):
        """

        PARAMETERS
        ----------
        
        `rounds` : int, default=5
            Set how many rounds the SPN will run

        `vector_output` : bool, default=False
            Set to `True` if output should be a vector
            binary representation of the output integer
            
        `round_keys` : iterable, default=None
            Should be an iterable of length `self._rounds + 1`.
            Each entry is an integer OR an iterable 
            binary representation of an integer.
            Any key must be in `range(0xffff + 1)`.
            If no keys are provided, a random set 
            will be generated and used.
            
        """
        
        self._rounds = rounds
        self._pbox = [i+4*j for i in range(4) for j in range(4)] # [4*i % 15] + [15]
        self._sbox = SBox(6, 4, 0xc, 5, 0, 7, 2, 0xe, 1, 0xf,3, 0xd,8, 0xa, 9, 0xb)
        self._vec_out = vector_output
        
        self._round_keys = round_keys
    
    def __call__(self, input_, round_keys=None, alg=0):
        """
        Directly call an instance of cipher_four to either encrypt/decrypt `input_` with `round_keys`
        
        PARAMETERS
        ----------
        `plaintext` : int, iterable 
            Input to be encrypted.
            Can be an integer OR any iterable
            binary representation of an integer.
            Both must be in `range(0xffff + 1)`

        `round_keys` : iterable, default=None 
            Should be an iterable of length `self._rounds + 1`.
            Each entry is an integer OR an iterable 
            binary representation of an integer.
            Any key must be in `range(0xffff + 1)`
            If no keys are provided, a random set 
            will be generated and used.

        `alg` : int, default=0
            Determine whether to encrypt/decrypt `input_`:
            - `0` for encryption
            - `1` for decryption
        
        """
        
        if alg:
            return self.decrypt(input_, round_keys)
        
        return self.encrypt(input_, round_keys)
    
    def _repr_(self):
        return f"cipher_four(rounds={self._rounds}, vector_output={self._vec_out})"
    
    # Getter and setter for round_keys
    # for tests, when I'm too lazy to pass a key
    @property
    def round_keys(self):
        return self._round_keys
    
    @round_keys.setter
    def round_keys(self, keys):
        if len(keys) < self._rounds:
            raise Exception(f"Not enough keys ({len(keys)}) for specified parameters (rounds={self._rounds})")
        
        self._round_keys = keys
    
    # -------------------------------- Encryption -------------------------------- #
    def encrypt(self, plaintext, round_keys=None):
        """
        cipher_four encryption of the `plaintext` with `round_keys`
        
        PARAMETERS
        ----------
        
        `plaintext` : int, iterable 
            Input to be encrypted.
            Can be an integer OR any iterable
            binary representation of an integer.
            Both must be in `range(0xffff + 1)`

        `round_keys` : iterable, default=None 
            Should be an iterable of length `self._rounds + 1`.
            Each entry is an integer OR an iterable 
            binary representation of an integer.
            Any key must be in `range(0xffff + 1)` 
            If no keys are provided, a random set 
            will be generated and used.
        
        """
        
        state = cipher_four.iter_to_int(plaintext)
        
        if not round_keys:
            self.round_keys = self.generate_keys()
            round_keys = self.round_keys
        
        # first r - 1 rounds
        for key in round_keys[:self._rounds-1]:
            state = self.round(state, key)
            
        # last round
        state = self.add_round_key(state, round_keys[self._rounds-1])
        state = self.sbox_layer(state)
        state = self.add_round_key(state, round_keys[self._rounds])
        
        if self._vec_out:
            return cipher_four.int_to_vec(state)
        
        return state
        
    # -------------------------------- Decryption -------------------------------- #
    def decrypt(self, ciphertext, round_keys=None):
        """
        cipher_four decryption of the `cipher` with `round_keys`
        
        PARAMETERS
        ----------

        `ciphertext` : int, iterable 
            Input to be encrypted.
            Can be an integer OR any iterable
            binary representation of an integer.
            Both must be in `range(0xffff + 1)`

        `round_keys` : iterable, default=None 
            Should be an iterable of length `self._rounds + 1`.
            Each entry is an integer OR an iterable 
            binary representation of an integer.
            Any key must be in `range(0xffff + 1)` 
            If no keys are provided, a random set 
            will be generated and used.
        """
        
        state = cipher_four.iter_to_int(ciphertext)
        
        if state and not state % (0xffff + 1):
            raise ValueError(f"Value of the state ({state}) is not allowed")
        
        if round_keys is None:
            if self.round_keys is None:
                raise Exception("You want to decrypt something without a key? How cheeky.")
            round_keys = self.round_keys
        
        # 'first' round
        state = self.add_round_key(state, round_keys[self._rounds])
        state = self.sbox_layer(state, inverse=True)
        state = self.add_round_key(state, round_keys[self._rounds-1])
        
        for key in round_keys[self._rounds-2::-1]:
            state = self.round(state, key, inverse=True)
        
        if self._vec_out:
            return cipher_four.int_to_vec(state)
        
        return state
    
    def round(self, state, round_key, inverse=False):
        
        if inverse:
            state = self.perm_layer(state)
            state = self.sbox_layer(state, inverse)
            state = self.add_round_key(state, round_key)
            return state
        
        state = self.add_round_key(state, round_key)
        state = self.sbox_layer(state, inverse)
        state = self.perm_layer(state)
        
        return state
    
    # ---------------------------- Substitution Layer ---------------------------- #
    def sbox_layer(self, state, inverse=False):
        
        # sanity check
        if state and not state % (0xffff + 1):
            raise ValueError("Value of the state is not allowed")
        # back to work
        
        if inverse:
            sbox = self._sbox.inverse()
        else:
            sbox = self._sbox
        
        res = 0
        
        for i in range(0, 16, 4):
            nib = (state >> i) & 0xf
            res |= sbox(nib) << i
                
        return res
    
    # ----------------------------- Permutation Layer ---------------------------- #
    def perm_layer(self, state):
        
        # sanity check
        if state and not state % (0xffff + 1):
            raise ValueError("Value of the state is not allowed")
        # back to work
            
        p_state = 0

        # 4*i % 15
        for bit_index, perm_index in enumerate(self._pbox):
            if(state & (1 << bit_index)):       # IF bit at `bit_index` is 1
                p_state |= (1 << perm_index)    # Set the bit at `perm_index` to 1 
        
        return p_state
    
    # ------------------------------- Add Round Key ------------------------------ #
    def add_round_key(self, state, round_key):
        
        # sanity check (I really shouldn't have so much repetition)
        if state and not state % (0xffff + 1):
            raise ValueError(f"Value of the state ({state}) is not allowed")
            
        if not isinstance(round_key, (Integer, int)):
            try:
                round_key = cipher_four.iter_to_int(round_key)
            except TypeError:
                print(f"Type of the round_key ({type(round_key)}) is not allowed")
        # back to work

        return state ^ round_key # ok, carful with ^ in sage

    # ----------------------------------- Utils ---------------------------------- #
    def int_to_vec(state):
        return vector(GF(2), ZZ(state).digits(2))
    
    def iter_to_int(state):
        if isinstance(state, (Integer, int)):
            return state
        return ZZ(list(state), 2)
    
    def generate_keys(self):
        from random import SystemRandom
        key_gen = SystemRandom()
        return [key_gen.randrange(0xffff) for i in range(self._rounds + 1)]
