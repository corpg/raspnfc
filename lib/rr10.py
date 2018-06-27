#!/usr/bin/python

#import serial

"""
Sequence:
    Host             Reader
      ------ 0x55 ---->       Ready to send
      <----- 0xAA -----          Ready to receive
      ------ CMD ----->       Request
      
      <----- 0xA5 -----          Ready to send
      ------ 0x5A ---->          Ready to receive
      <----- DATA -----          Response
"""
# prototype
class NFCSerial:
    def __init__(self):
        self.mode = None
    
class RR10(NFCSerial):
    def __init__(self, serial):
        self.serial = serial
        
    def send(self, message):
        if self.prepare_to_send():
            return self.serial.write(message)
        return 0
        
    def receive(self):
        if not self.prepare_to_receive():
            return None
        # first read length
        length = self.serial.read(1)
        data = self.serial.read(int(length.hex(), 16))
        return Message(length + data)
        
    # synchronize with reader - is he ready to receive ?
    def prepare_to_send(self):
        self.serial.write(b'\x55')
        # block until we got the sync character
        s = self.serial.read(1)
        if s != b'\xAA':
            print('Received: {:#x} instead of 0xAA'.format(s))
            # if this happens, it means we read a block while receiving other data ?
            return False
        return True
        
    # synchronize with device - are we ready to receive ?
    def ready_to_receive(self):
        s = self.serial.read(1)
        if s != b'\xA5':
            print('Received: {:#x} instead of 0xA5'.format(s))
            return False
        return 1 == self.serial.write(b'\x5A')


class Message(bytearray):
    INDEX_LENGTH = 0
    INDEX_COMMAND = 1
    INDEX_PARAMETERS = 2
    INDEX_CHECKSUM = -2
    
    # 1 byte for length, 1 byte for command, 2 bytes for checksum
    MIN_LENGTH = 4
    MAX_LENGTH = 255
    MAX_PARAMETERS = 251
    
    # Available commands
    COMMAND_CONNECTION = 0x01
    COMMAND_SELECT_RF = 0x02
    COMMAND_GET_VERSION = 0x03
    COMMAND_ISO15693_TAG_INVENTORY = 0x06
    COMMAND_ISO15693_TAG_ACCESS = 0x07
    COMMAND_ISO14443A_TAS_ACCESS = 0x08
    COMMAND_ISO14443A_TAG_INVENTORY = 0x09
    COMMAND_MIFARE_ULTRALIGHT_TAG_ACCESS = 0x08 # compatible ISO14443A
    COMMAND_TOPAZ_TAG_INVENTORY = 0x0F # compatible ISO14443A
    COMMAND_TOPAZ_TAG_ACCESS = 0x0F # compatible ISO14443A
    COMMAND_ST_TAG_INVENTORY = 0x0A # compatible ISO14443B
    COMMAND_ST_TAG_ACCESS = 0x0B # compatible ISO14443B
    COMMAND_ISO14443B_TAG_INVENTORY = 0x0C
    COMMAND_ISO14443B_TAG_ACCESS = 0x0D
    COMMAND_FELICA_TAG_INVENTORY = 0x0E
    #COMMAND_MSTAR_P2P_TX = 0x1E
    #COMMAND_MSTAR_P2P_RX = 0x1F
    COMMAND_DEVICE_SET_TARGET = 0x20 # ISO18092
    COMMAND_DEVICE_SET_INITIATOR = 0x21 # ISO18092
    
    def __init__(self, command_or_sequence, *parameters):
        """
        Create a new message.
        Constructor:
            - Message(command, parameters)
            - Message(bytearray or sequence of bytes)
        """
        if isinstance(command_or_sequence, bytes) or isinstance(command_or_sequence, bytearray):
            super(Message, self).__init__(command_or_sequence)
            length = len(self)
            if length > self.MAX_LENGTH:
                raise Exception('Error: Message too long')
            if length != self.length:
                raise Exception('Error: Incorrect message length ({:#x}).\n'.format(len(self)))
            checksum = self.get_checksum()
            if checksum != self.checksum:
                raise Exception('Error: Incorrect message checksum (0x{}).\n'.format(checksum.hex()))
        elif isinstance(command_or_sequence, int):
            super(Message, self).__init__(self.MIN_LENGTH + len(parameters))
            self.command = command_or_sequence
            self.parameters = bytearray(parameters)
        else:
            raise Exception('Unknown constructor...')
        
    def __repr__(self):
        return '{}({})'.format(self.__class__.__name__, bytes(self))        
        #return '{}({}, {})'.format(self.__class__.__name__, hex(self.command), ', '.join((hex(p) for p in self.parameters)))
    
    @property
    def checksum(self):
        return self[self.INDEX_CHECKSUM:]
        
    def get_checksum(self):
        return sum(self[:self.INDEX_CHECKSUM]).to_bytes(2, 'little')
        
    def _update_checksum(self):
        """
        Update message checksum.
        Should always be called when there is a change in length, command or parameters.
        """
        self[self.INDEX_CHECKSUM:] = self.get_checksum()
        
    @property
    def length(self):
        return self[self.INDEX_LENGTH]

    def _update_length(self):
        """
        Update message length.
        Should always be called when there is a change in the parameters.
        Also update checksum.
        """
        self[self.INDEX_LENGTH] = len(self)
        self._update_checksum()
        
    @property
    def parameters(self):
        parameters = getattr(self, "_parameters", None)
        if not parameters:
            # parameters are between command and checksum
            parameters = self.__class__.ParametersArray(self, self[self.INDEX_PARAMETERS:self.INDEX_CHECKSUM])
            setattr(self, "_parameters", parameters)
        return parameters
        
    @parameters.setter
    def parameters(self, value):
        if not isinstance(value, bytearray):
            raise Exception("Parameters must be a bytearray")
        if len(value) > self.MAX_PARAMETERS:
            raise Exception("Too many parameters. Maximum {}".format(self.MAX_PARAMETERS))
        if len(value) + self.MIN_LENGTH != len(self):
            # expand array
            self += bytearray( (len(value) + self.MIN_LENGTH)- len(self) )
        # set new parameters
        self[self.INDEX_PARAMETERS:self.INDEX_CHECKSUM] = value
        self._update_length()
        # update private property
        if not isinstance(value, self.__class__.ParametersArray):
            setattr(self, "_parameters", self.__class__.ParametersArray(self, value))
        
    @property
    def command(self):
        return self[self.INDEX_COMMAND]
        
    @command.setter
    def command(self, command):
        if command not in self.get_commands().values():
            raise Exception('Unknow command {}'.format(command))
        self[self.INDEX_COMMAND] = command
        self._update_checksum()
        
    @classmethod
    def version(cls):
        return cls(cls.COMMAND_GET_VERSION)
        
    @classmethod
    def test(cls):
        return cls(cls.COMMAND_CONNECTION, 0x05, 0x0A)
        
    @classmethod
    def get_commands(cls):
        commands = getattr(cls, "__commands", [])
        if not commands:
            # parse class attributes
            commands = dict([ (key, value) for key, value in vars(cls).items() if key.startswith('COMMAND_') ])
            setattr(cls, "__commands", commands)
        return commands
        
#    @classmethod
#    def frombytearray(cls, value):
#        """
#        Initialize a message from a bytearray.
#        """
#        if isinstance(value, bytes):
#            value = bytearray(value)
#        if not isinstance(value, bytearray):
#            raise ValueError("'{0.__name__}' given, 'bytearray' expected.".format(type(value)))
#        message = cls(value[1])
##        # this won't change the checksum value and length
#        message[:] = value
#        return message
        
    ## Inner class for parameters
    class ParametersArray(bytearray):
        def __init__(self, message, args):
            self.message = message
            super(self.message.ParametersArray, self).__init__(args)
            
        def update_message(self):
            self.message.parameters = self
            
        def __setitem__(self, key, value):
            super(self.message.ParametersArray, self).__setitem__(key, value)
            self.update_message()
            
        def append(self, value):
            super(self.message.ParametersArray, self).append(value)
            self.update_message()
            
        ## other methods
        