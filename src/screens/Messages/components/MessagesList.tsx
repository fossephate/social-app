// import 'react-native-crypto'

import React, {useCallback, useRef} from 'react'
import {LayoutChangeEvent, View} from 'react-native'
import {useKeyboardHandler} from 'react-native-keyboard-controller'
import Animated, {
  runOnJS,
  scrollTo,
  useAnimatedRef,
  useAnimatedStyle,
  useSharedValue,
} from 'react-native-reanimated'
import {ReanimatedScrollEvent} from 'react-native-reanimated/lib/typescript/hook/commonTypes'
import {useSafeAreaInsets} from 'react-native-safe-area-context'
import * as SecureStore from 'expo-secure-store'
import {AppBskyEmbedRecord, AppBskyRichtextFacet, RichText} from '@atproto/api'

import {clamp} from '#/lib/numbers'
import {ScrollProvider} from '#/lib/ScrollContext'
import {shortenLinks, stripInvalidMentions} from '#/lib/strings/rich-text-manip'
import {
  convertBskyAppUrlIfNeeded,
  isBskyPostUrl,
} from '#/lib/strings/url-helpers'
import {logger} from '#/logger'
import {isNative} from '#/platform/detection'
import {isWeb} from '#/platform/detection'
import {isConvoActive, useConvoActive} from '#/state/messages/convo'
import {ConvoItem, ConvoStatus} from '#/state/messages/convo/types'
import {useGetPost} from '#/state/queries/post'
import {useAgent} from '#/state/session'
import {
  EmojiPicker,
  EmojiPickerState,
} from '#/view/com/composer/text-input/web/EmojiPicker.web'
import {List, ListMethods} from '#/view/com/util/List'
import {ChatDisabled} from '#/screens/Messages/components/ChatDisabled'
import {MessageInput} from '#/screens/Messages/components/MessageInput'
import {MessageListError} from '#/screens/Messages/components/MessageListError'
import {ChatEmptyPill} from '#/components/dms/ChatEmptyPill'
import {MessageItem} from '#/components/dms/MessageItem'
import {NewMessagesPill} from '#/components/dms/NewMessagesPill'
import {Loader} from '#/components/Loader'
import {Text} from '#/components/Typography'
import {MessageInputEmbed, useMessageEmbed} from './MessageInputEmbed'
// import WebviewCrypto from 'react-native-webview-crypto'
// let QuickCrypto: any;
// if (!isWeb) {
//   QuickCrypto = require('react-native-quick-crypto');
// }
// import * as QuickCrypto from 'react-native-quick-crypto';
// QuickCrypto.install();
let Crypto: any
if (!isWeb) {
  Crypto = require('react-native-quick-crypto')
}

function MaybeLoader({isLoading}: {isLoading: boolean}) {
  return (
    <View
      style={{
        height: 50,
        width: '100%',
        alignItems: 'center',
        justifyContent: 'center',
      }}>
      {isLoading && <Loader size="xl" />}
    </View>
  )
}

function renderItem({item}: {item: ConvoItem}) {
  if (item.type === 'message' || item.type === 'pending-message') {
    return <MessageItem item={item} />
  } else if (item.type === 'deleted-message') {
    return <Text>Deleted message</Text>
  } else if (item.type === 'error') {
    return <MessageListError item={item} />
  }

  return null
}

function keyExtractor(item: ConvoItem) {
  return item.key
}

function onScrollToIndexFailed() {
  // Placeholder function. You have to give FlatList something or else it will error.
}

async function generateMessageKeyPair() {
  let subtle
  if (isWeb) {
    subtle = window.crypto.subtle
  } else {
    subtle = Crypto.subtle
  }
  return await subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt'],
  )
}

async function encryptWithPublicKey(text: string, publicKey: any) {
  const encoded = new TextEncoder().encode(text)
  let subtle
  if (isWeb) {
    subtle = window.crypto.subtle
  } else {
    subtle = Crypto.subtle
  }
  const encrypted = await subtle.encrypt({name: 'RSA-OAEP'}, publicKey, encoded)
  return btoa(String.fromCharCode(...new Uint8Array(encrypted)))
}

async function importPubkey(key: string) {
  let subtle
  if (isWeb) {
    subtle = window.crypto.subtle
  } else {
    subtle = Crypto.subtle
  }
  let importedKey = await subtle.importKey(
    'jwk',
    JSON.parse(key), // The exported JWK object
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256',
    },
    true,
    ['encrypt'], // For public key
  )
  return importedKey
}

async function exportPubkey(key: any) {
  let subtle
  if (isWeb) {
    subtle = window.crypto.subtle
  } else {
    subtle = Crypto.subtle
  }
  let exported = await subtle.exportKey('jwk', key)
  if (!isWeb) {
    exported.n = exported.n.replace(/\.+$/, '')
  }
  console.log('exportedPubkey n:', exported.n)
  return JSON.stringify(exported)
}

async function decryptWithPrivateKey(
  encryptedText: string,
  privateKey: CryptoKey,
) {
  let subtle
  if (isWeb) {
    subtle = window.crypto.subtle
  } else {
    subtle = Crypto.subtle
  }
  const encryptedData = Uint8Array.from(atob(encryptedText), c =>
    c.charCodeAt(0),
  )
  const decrypted = await subtle.decrypt(
    {name: 'RSA-OAEP'},
    privateKey,
    encryptedData,
  )
  return new TextDecoder().decode(decrypted)
}

function stripDid(did: string) {
  return did.split(':')[2].trim()
}

function sanitizeKey(key: string) {
  // replace any non-alphanumeric non-underscore, non-dash, non-period characters with an underscore:
  return key.replace(/[^a-zA-Z0-9_.-]/g, '_')
}

// wrap secure store / use local storage instead of secure store on web:
function getItem(key: string) {
  // console.log('getting item:', key)
  key = sanitizeKey(key)
  if (isWeb) {
    return localStorage.getItem(key)
  } else {
    return SecureStore.getItem(key)
  }
}

async function setItem(key: string, value: string) {
  // console.log('setting item:', key, value)
  key = sanitizeKey(key)
  if (isWeb) {
    return localStorage.setItem(key, value)
  } else {
    return SecureStore.setItemAsync(key, value)
  }
}

const isBase64 = (str: string) =>
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(str)

async function getKeyPair(did: string) {
  return JSON.parse((await getItem(did)) || '{}')
}

async function getOrCreateKeyPair(did: string) {
  let subtle
  if (isWeb) {
    subtle = window.crypto.subtle
  } else {
    subtle = Crypto.subtle
  }

  // check if we have a keypair for our did
  let keyPair = await getKeyPair(did)
  if (!keyPair.privateKey) {
    console.log('no keypair found for our did! generating keypair...')
    keyPair = await generateMessageKeyPair()
    console.log('generated keypair:')

    const exported = {
      publicKey: await subtle.exportKey('jwk', keyPair.publicKey),
      privateKey: await subtle.exportKey('jwk', keyPair.privateKey),
    }

    const serialized = JSON.stringify(exported)
    await setItem(did, serialized)

    return keyPair
  } else {
    const imported = {
      publicKey: await subtle.importKey(
        'jwk',
        keyPair.publicKey,
        {name: 'RSA-OAEP', hash: 'SHA-256'},
        true,
        ['encrypt'],
      ),
      privateKey: await subtle.importKey(
        'jwk',
        keyPair.privateKey,
        {name: 'RSA-OAEP', hash: 'SHA-256'},
        true,
        ['decrypt'],
      ),
    }
    return imported
  }
}

function updateMessage(items: ConvoItem[], messageId: string, text: string) {
  return items.map(item => {
    if (item.type !== 'message' && item.type !== 'pending-message') {
      return item
    }
    if (item.message.id === messageId) {
      item.message.text = text
    }
    return item
  })
}

export function MessagesList({
  hasScrolled,
  setHasScrolled,
  blocked,
  footer,
}: {
  hasScrolled: boolean
  setHasScrolled: React.Dispatch<React.SetStateAction<boolean>>
  blocked?: boolean
  footer?: React.ReactNode
}) {
  const convoState = useConvoActive()
  const agent = useAgent()
  const getPost = useGetPost()
  const {embedUri, setEmbed} = useMessageEmbed()
  const [notReplied, setNotReplied] = React.useState(false)

  const flatListRef = useAnimatedRef<ListMethods>()

  const [newMessagesPill, setNewMessagesPill] = React.useState({
    show: false,
    startContentOffset: 0,
  })

  const [emojiPickerState, setEmojiPickerState] =
    React.useState<EmojiPickerState>({
      isOpen: false,
      pos: {top: 0, left: 0, right: 0, bottom: 0, nextFocusRef: null},
    })

  // We need to keep track of when the scroll offset is at the bottom of the list to know when to scroll as new items
  // are added to the list. For example, if the user is scrolled up to 1iew older messages, we don't want to scroll to
  // the bottom.
  const isAtBottom = useSharedValue(true)

  // This will be used on web to assist in determining if we need to maintain the content offset
  const isAtTop = useSharedValue(true)

  // Used to keep track of the current content height. We'll need this in `onScroll` so we know when to start allowing
  // onStartReached to fire.
  const prevContentHeight = useRef(0)
  const prevItemCount = useRef(0)

  // -- Keep track of background state and positioning for new pill
  const layoutHeight = useSharedValue(0)
  const didBackground = React.useRef(false)
  React.useEffect(() => {
    if (convoState.status === ConvoStatus.Backgrounded) {
      didBackground.current = true
    }
  }, [convoState.status])

  // -- Scroll handling

  // Every time the content size changes, that means one of two things is happening:
  // 1. New messages are being added from the log or from a message you have sent
  // 2. Old messages are being prepended to the top
  //
  // The first time that the content size changes is when the initial items are rendered. Because we cannot rely on
  // `initialScrollIndex`, we need to immediately scroll to the bottom of the list. That scroll will not be animated.
  //
  // Subsequent resizes will only scroll to the bottom if the user is at the bottom of the list (within 100 pixels of
  // the bottom). Therefore, any new messages that come in or are sent will result in an animated scroll to end. However
  // we will not scroll whenever new items get prepended to the top.
  const onContentSizeChange = useCallback(
    (_: number, height: number) => {
      // Because web does not have `maintainVisibleContentPosition` support, we will need to manually scroll to the
      // previous off whenever we add new content to the previous offset whenever we add new content to the list.
      if (isWeb && isAtTop.get() && hasScrolled) {
        flatListRef.current?.scrollToOffset({
          offset: height - prevContentHeight.current,
          animated: false,
        })
      }

      // This number _must_ be the height of the MaybeLoader component
      if (height > 50 && isAtBottom.get()) {
        // If the size of the content is changing by more than the height of the screen, then we don't
        // want to scroll further than the start of all the new content. Since we are storing the previous offset,
        // we can just scroll the user to that offset and add a little bit of padding. We'll also show the pill
        // that can be pressed to immediately scroll to the end.
        if (
          didBackground.current &&
          hasScrolled &&
          height - prevContentHeight.current > layoutHeight.get() - 50 &&
          convoState.items.length - prevItemCount.current > 1
        ) {
          flatListRef.current?.scrollToOffset({
            offset: prevContentHeight.current - 65,
            animated: true,
          })
          setNewMessagesPill({
            show: true,
            startContentOffset: prevContentHeight.current - 65,
          })
        } else {
          flatListRef.current?.scrollToOffset({
            offset: height,
            animated: hasScrolled && height > prevContentHeight.current,
          })

          // HACK Unfortunately, we need to call `setHasScrolled` after a brief delay,
          // because otherwise there is too much of a delay between the time the content
          // scrolls and the time the screen appears, causing a flicker.
          // We cannot actually use a synchronous scroll here, because `onContentSizeChange`
          // is actually async itself - all the info has to come across the bridge first.
          if (!hasScrolled && !convoState.isFetchingHistory) {
            setTimeout(() => {
              setHasScrolled(true)
            }, 100)
          }
        }
      }

      prevContentHeight.current = height
      prevItemCount.current = convoState.items.length
      didBackground.current = false
    },
    [
      hasScrolled,
      setHasScrolled,
      convoState.isFetchingHistory,
      convoState.items, // these are stable
      flatListRef,
      isAtTop,
      isAtBottom,
      layoutHeight,
    ],
  )

  const onStartReached = useCallback(() => {
    if (hasScrolled && prevContentHeight.current > layoutHeight.get()) {
      convoState.fetchMessageHistory()
    }
  }, [convoState, hasScrolled, layoutHeight])

  const onScroll = React.useCallback(
    (e: ReanimatedScrollEvent) => {
      'worklet'
      layoutHeight.set(e.layoutMeasurement.height)
      const bottomOffset = e.contentOffset.y + e.layoutMeasurement.height

      // Most apps have a little bit of space the user can scroll past while still automatically scrolling ot the bottom
      // when a new message is added, hence the 100 pixel offset
      isAtBottom.set(e.contentSize.height - 100 < bottomOffset)
      isAtTop.set(e.contentOffset.y <= 1)

      if (
        newMessagesPill.show &&
        (e.contentOffset.y > newMessagesPill.startContentOffset + 200 ||
          isAtBottom.get())
      ) {
        runOnJS(setNewMessagesPill)({
          show: false,
          startContentOffset: 0,
        })
      }
    },
    [layoutHeight, newMessagesPill, isAtBottom, isAtTop],
  )

  // -- Keyboard animation handling
  const {bottom: bottomInset} = useSafeAreaInsets()
  const bottomOffset = isWeb ? 0 : clamp(60 + bottomInset, 60, 75)

  const keyboardHeight = useSharedValue(0)
  const keyboardIsOpening = useSharedValue(false)

  // In some cases - like when the emoji piker opens - we don't want to animate the scroll in the list onLayout event.
  // We use this value to keep track of when we want to disable the animation.
  const layoutScrollWithoutAnimation = useSharedValue(false)

  useKeyboardHandler(
    {
      onStart: e => {
        'worklet'
        // Immediate updates - like opening the emoji picker - will have a duration of zero. In those cases, we should
        // just update the height here instead of having the `onMove` event do it (that event will not fire!)
        if (e.duration === 0) {
          layoutScrollWithoutAnimation.set(true)
          keyboardHeight.set(e.height)
        } else {
          keyboardIsOpening.set(true)
        }
      },
      onMove: e => {
        'worklet'
        keyboardHeight.set(e.height)
        if (e.height > bottomOffset) {
          scrollTo(flatListRef, 0, 1e7, false)
        }
      },
      onEnd: e => {
        'worklet'
        keyboardHeight.set(e.height)
        if (e.height > bottomOffset) {
          scrollTo(flatListRef, 0, 1e7, false)
        }
        keyboardIsOpening.set(false)
      },
    },
    [bottomOffset],
  )

  const animatedListStyle = useAnimatedStyle(() => ({
    marginBottom: Math.max(keyboardHeight.get(), bottomOffset),
  }))

  const animatedStickyViewStyle = useAnimatedStyle(() => ({
    transform: [{translateY: -Math.max(keyboardHeight.get(), bottomOffset)}],
  }))

  // -- Message sending
  const onSendMessage = useCallback(
    async (text: string) => {
      let rt = new RichText({text: text.trimEnd()}, {cleanNewlines: true})

      // detect facets without resolution first - this is used to see if there's
      // any post links in the text that we can embed. We do this first because
      // we want to remove the post link from the text, re-trim, then detect facets
      rt.detectFacetsWithoutResolution()

      let embed: AppBskyEmbedRecord.Main | undefined

      if (embedUri) {
        try {
          const post = await getPost({uri: embedUri})
          if (post) {
            embed = {
              $type: 'app.bsky.embed.record',
              record: {
                uri: post.uri,
                cid: post.cid,
              },
            }

            // look for the embed uri in the facets, so we can remove it from the text
            const postLinkFacet = rt.facets?.find(facet => {
              return facet.features.find(feature => {
                if (AppBskyRichtextFacet.isLink(feature)) {
                  if (isBskyPostUrl(feature.uri)) {
                    const url = convertBskyAppUrlIfNeeded(feature.uri)
                    const [_0, _1, _2, rkey] = url.split('/').filter(Boolean)

                    // this might have a handle instead of a DID
                    // so just compare the rkey - not particularly dangerous
                    return post.uri.endsWith(rkey)
                  }
                }
                return false
              })
            })

            if (postLinkFacet) {
              const isAtStart = postLinkFacet.index.byteStart === 0
              const isAtEnd =
                postLinkFacet.index.byteEnd === rt.unicodeText.graphemeLength

              // remove the post link from the text
              if (isAtStart || isAtEnd) {
                rt.delete(
                  postLinkFacet.index.byteStart,
                  postLinkFacet.index.byteEnd,
                )
              }

              rt = new RichText({text: rt.text.trim()}, {cleanNewlines: true})
            }
          }
        } catch (error) {
          logger.error('Failed to get post as quote for DM', {error})
        }
      }

      await rt.detectFacets(agent)

      rt = shortenLinks(rt)
      rt = stripInvalidMentions(rt)

      if (!hasScrolled) {
        setHasScrolled(true)
      }

      console.log('onSendMessage called with text:', text)

      if (!agent.did) {
        console.error('agent.did is undefined')
        return
      }

      if (!convoState.recipients[0].did) {
        console.error('convoState.recipients[0].did is undefined')
        return
      }

      const ourDid = stripDid(agent.did)
      const recipientDid = stripDid(convoState.recipients[0].did)
      // first check if we have a keypair for our did
      console.log('ourDid:', ourDid)
      console.log('recipientDid:', recipientDid)
      let haveOwnKeyPair = (await getKeyPair(ourDid)).privateKey !== undefined
      let keyPair = await getOrCreateKeyPair(ourDid)

      // sanity check, encrypt and decrypt a message with our key pair:
      // const encryptedText = await encryptWithPublicKey(rt.text, keyPair.publicKey)
      // const decryptedText = await decryptWithPrivateKey(encryptedText, keyPair.privateKey)
      // console.log('original text:', rt.text)
      // console.log('encryptedText:', encryptedText)
      // console.log('decryptedText:', decryptedText)

      // post a message with pub:<ourPubKey>
      // and then post a message encrypted with their pubKey if they have one:
      // get their pubKey from the store
      const recipientPubkey = await getItem(`pubkey_${recipientDid}`)
      // console.log('recipientPubkey:', recipientPubkey)

      let importedKey: any

      try {
        importedKey = await importPubkey(recipientPubkey ?? '')
      } catch (e) {
        console.log('Error importing pubkey:', e)
      }

      // if we didn't have a key pair, or we don't have their pubkey, we must send our pubkey:
      if (
        importedKey === null ||
        importedKey === undefined ||
        notReplied ||
        !haveOwnKeyPair
      ) {
        console.log(
          'recipientPubkey is null or undefined! sending our pubkey...',
        )
        // they haven't sent their pubKey yet!:
        // just send our pubkey:

        const exportedPubkey: string = await exportPubkey(keyPair.publicKey)

        let pubkeyText = btoa(`pubkey_${exportedPubkey}`)
        if (notReplied) {
          pubkeyText = btoa(`pubkeyrep_${exportedPubkey}`)
        }
        convoState.sendMessage({
          text: pubkeyText,
          facets: rt.facets,
          embed,
        })
        setNotReplied(false)

        // if we have their pubkey, we can still send an encrypted message in addition to our pubkey:
        if (importedKey !== null) {
          try {
            // encrypt our message with their public key
            const encryptedText = `enc_${await encryptWithPublicKey(
              rt.text,
              importedKey,
            )}`
            // base64 encode the text
            const base64Text = btoa(encryptedText)
            // add a message override:
            await setItem(`override_${base64Text}`, rt.text)
            // send the message with the encrypted text
            convoState.sendMessage({
              text: base64Text,
              facets: rt.facets,
              embed,
            })
          } catch (e) {
            console.log('Error encrypting message:', e)
          }
        }
        return
      } else {
        try {
          // encrypt our message with their public key
          const encryptedText = `enc_${await encryptWithPublicKey(
            rt.text,
            importedKey,
          )}`
          // base64 encode the text
          const base64Text = btoa(encryptedText)
          // add a message override:
          await setItem(`override_${base64Text}`, rt.text)
          // send the message with the encrypted text
          convoState.sendMessage({
            text: base64Text,
            facets: rt.facets,
            embed,
          })
        } catch (e) {
          console.log('Error encrypting message:', e)
          convoState.sendMessage({
            text: 'Failed to encrypt message',
            facets: rt.facets,
            embed,
          })
        }
        return
      }
    },
    [
      agent,
      convoState,
      embedUri,
      getPost,
      hasScrolled,
      setHasScrolled,
      notReplied,
    ],
  )

  // -- List layout changes (opening emoji keyboard, etc.)
  const onListLayout = React.useCallback(
    (e: LayoutChangeEvent) => {
      layoutHeight.set(e.nativeEvent.layout.height)

      if (isWeb || !keyboardIsOpening.get()) {
        flatListRef.current?.scrollToEnd({
          animated: !layoutScrollWithoutAnimation.get(),
        })
        layoutScrollWithoutAnimation.set(false)
      }
    },
    [
      flatListRef,
      keyboardIsOpening,
      layoutScrollWithoutAnimation,
      layoutHeight,
    ],
  )

  const scrollToEndOnPress = React.useCallback(() => {
    flatListRef.current?.scrollToOffset({
      offset: prevContentHeight.current,
      animated: true,
    })
  }, [flatListRef])

  // Log new messages when they arrive
  let items = convoState.items.slice(0)
  const newItems = convoState.items.slice(prevItemCount.current)
  newItems.forEach(async item => {
    if (item.type !== 'message' && item.type !== 'pending-message') {
      return
    }
    let text = item.message.text
    const message = item.message
    const messageId = message.id
    const senderDid = stripDid(message.sender.did)
    const isLastMessage = items.length - 1 === items.indexOf(item)
    if (!agent.did) {
      return
    }
    const ourDid = stripDid(agent.did)
    if (senderDid !== ourDid) {
      console.log('New message received:', text)
    }

    let wasB64 = false
    // if the message is base64 encoded, decode it
    if (isBase64(text)) {
      text = atob(text)
      wasB64 = true
    }

    // if (senderDid === ourDid) {
    //   return
    // }

    if (text.startsWith('pubkey_') || text.startsWith('pubkeyrep_')) {
      let isReply = text.startsWith('pubkeyrep_')
      try {
        let prefix = isReply ? 'pubkeyrep_' : 'pubkey_'
        console.log(`New pubkey received from did: ${senderDid}`)
        const pubkey = JSON.parse(text.slice(prefix.length))
        await setItem(`pubkey_${senderDid}`, JSON.stringify(pubkey))
        // hide this message:
        await setItem(`override_${messageId}`, '')
        items = updateMessage(items, messageId, 'hidden')
        if (isLastMessage) {
          convoState.fetchMessageHistory()
        }

        // TODO: if someone just sent their pubkeyrep, we should send our last message again:

        // delete the message after 3 seconds:
        // setTimeout(() => {
        //   convoState.deleteMessage(messageId)
        // }, 1000)
        // convoState.deleteMessage()
        // respond with our pubkey:
        if (!isReply && senderDid !== ourDid) {
          console.log('sending pubkey reply on next message...')
          setNotReplied(true)
          // let keyPair = await getOrCreateKeyPair(ourDid)
          // let rt = new RichText({ text: text.trimEnd() }, { cleanNewlines: true })
          // convoState.sendMessage({
          //   text: atob(`pubkeyrep_${JSON.stringify(keyPair.publicKey)}`),
          //   facets: rt.facets,
          // })
          return
        }
      } catch (e) {
        console.error('Error setting pubkey:', e)
      }
    }

    if (senderDid === ourDid) {
      return
    }

    if (text.startsWith('enc_') && wasB64) {
      try {
        // attempt to decrypt using our private key
        let ourKeyPair = await getOrCreateKeyPair(ourDid)
        // console.log("ourKeyPair:", ourKeyPair)
        const decryptedText = await decryptWithPrivateKey(
          text.slice('enc_'.length),
          ourKeyPair.privateKey,
        )
        console.log('Decrypted text:', decryptedText)

        items = updateMessage(items, messageId, decryptedText ?? '')
        if (isLastMessage) {
          convoState.fetchMessageHistory()
        }
      } catch (e) {
        console.log('Error decrypting message:', e)
        // set an override for this message saying we failed to decrypt it:
        await setItem(
          `override_${messageId}`,
          'Failed to decrypt message, someone probably changed devices',
        )
        // if this is the last message in the list, we need to set notReplied to true
        if (isLastMessage) {
          setNotReplied(true)
          convoState.fetchMessageHistory()
        }
      }
    }
  })
  convoState.items = [...items]

  return (
    <>
      {/* Custom scroll provider so that we can use the `onScroll` event in our custom List implementation */}
      <ScrollProvider onScroll={onScroll}>
        <List
          ref={flatListRef}
          data={convoState.items}
          renderItem={renderItem}
          keyExtractor={keyExtractor}
          disableFullWindowScroll={true}
          disableVirtualization={true}
          style={animatedListStyle}
          // The extra two items account for the header and the footer components
          initialNumToRender={isNative ? 32 : 62}
          maxToRenderPerBatch={isWeb ? 32 : 62}
          keyboardDismissMode="on-drag"
          keyboardShouldPersistTaps="handled"
          maintainVisibleContentPosition={{
            minIndexForVisible: 0,
          }}
          removeClippedSubviews={false}
          sideBorders={false}
          onContentSizeChange={onContentSizeChange}
          onLayout={onListLayout}
          onStartReached={onStartReached}
          onScrollToIndexFailed={onScrollToIndexFailed}
          scrollEventThrottle={100}
          ListHeaderComponent={
            <MaybeLoader isLoading={convoState.isFetchingHistory} />
          }
        />
      </ScrollProvider>
      <Animated.View style={animatedStickyViewStyle}>
        {convoState.status === ConvoStatus.Disabled ? (
          <ChatDisabled />
        ) : blocked ? (
          footer
        ) : (
          <>
            {isConvoActive(convoState) &&
              !convoState.isFetchingHistory &&
              convoState.items.length === 0 && <ChatEmptyPill />}
            <MessageInput
              onSendMessage={onSendMessage}
              hasEmbed={!!embedUri}
              setEmbed={setEmbed}
              openEmojiPicker={pos => setEmojiPickerState({isOpen: true, pos})}>
              <MessageInputEmbed embedUri={embedUri} setEmbed={setEmbed} />
            </MessageInput>
          </>
        )}
      </Animated.View>

      {isWeb && (
        <EmojiPicker
          pinToTop
          state={emojiPickerState}
          close={() => setEmojiPickerState(prev => ({...prev, isOpen: false}))}
        />
      )}

      {newMessagesPill.show && <NewMessagesPill onPress={scrollToEndOnPress} />}
    </>
  )
}
