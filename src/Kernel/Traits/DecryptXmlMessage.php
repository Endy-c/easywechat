<?php

namespace EasyWeChat\Kernel\Traits;

use EasyWeChat\Kernel\Encryptor;
use EasyWeChat\Kernel\Exceptions\BadRequestException;
use EasyWeChat\Kernel\Message;
use EasyWeChat\Kernel\Support\Xml;
use JsonException;

/**
 * @SuppressWarnings("StaticAccess")
 */
trait DecryptXmlMessage
{
    /**
     * @throws \EasyWeChat\Kernel\Exceptions\RuntimeException
     * @throws BadRequestException
     */
    public function decryptMessage(
        Message $message,
        Encryptor $encryptor,
        string $signature,
        int|string $timestamp,
        string $nonce
    ): Message {
        $ciphertext = $message->Encrypt;

        $this->validateSignature($encryptor->getToken(), $ciphertext, $signature, $timestamp, $nonce);
        $decrypted = $encryptor->decrypt(
            ciphertext: $ciphertext,
            msgSignature: $signature,
            nonce: $nonce,
            timestamp: $timestamp
        );
        if ($this->isJson($decrypted)) {
            $message->merge(json_decode($decrypted, true));
            return $message;
        }
        $message->merge(Xml::parse($decrypted) ?? []);

        return $message;
    }

    protected function isJson($value)
    {
        if (!is_string($value)) {
            return false;
        }

        if (function_exists('json_validate')) {
            return json_validate($value, 512);
        }

        try {
            json_decode($value, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return false;
        }

        return true;
    }

    /**
     * @throws BadRequestException
     */
    protected function validateSignature(
        string $token,
        string $ciphertext,
        string $signature,
        int|string $timestamp,
        string $nonce
    ): void {
        if (empty($signature)) {
            throw new BadRequestException('Request signature must not be empty.');
        }

        $params = [$token, $timestamp, $nonce, $ciphertext];

        sort($params, SORT_STRING);

        if ($signature !== sha1(implode($params))) {
            throw new BadRequestException('Invalid request signature.');
        }
    }
}
