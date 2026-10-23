<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\EngineBlock;

use JointIdentityProvider\Core\Configuration\ConfigurationLoader;
use JointIdentityProvider\Core\Start\StartRequest;
use JointIdentityProvider\Core\Start\TransactionStarter;
use JointIdentityProvider\Core\Transaction\TransactionState;
use JsonException;
use stdClass;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The start call of EngineBlock's SBS interface (design §12, §13). JIP answers `interrupt` with a
 * non-empty nonce for every transaction it stored, and `error` when it stored none.
 */
final readonly class AuthzController
{
    // SBS message values (design §12); EngineBlock only logs `message`.
    public const string MSG_INTERRUPT = 'interrupt';
    public const string MSG_ERROR = 'error';
    public const string MESSAGE_LOGIN_REQUIRED = 'DEZI_LOGIN_REQUIRED';
    public const string MESSAGE_SKIPPED = 'DEZI_SKIPPED';

    public function __construct(
        private ConfigurationLoader $loader,
        private TransactionStarter $starter,
    ) {
    }

    #[Route('/authz', name: 'jip_sbs_authz', methods: ['POST'])]
    public function __invoke(Request $request): JsonResponse
    {
        $configuration = $this->loader->load();

        if (!ApiTokenAuthenticator::isAuthorized($request, $configuration->engineBlock->apiToken)) {
            return self::respond(['msg' => self::MSG_ERROR], Response::HTTP_UNAUTHORIZED);
        }

        try {
            $data = json_decode($request->getContent(), false, 16, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return self::respond(['msg' => self::MSG_ERROR], Response::HTTP_BAD_REQUEST);
        }

        if ($data instanceof stdClass) {
            $data = (array) $data;
            $attributes = $data['attributes'] ?? null;
            $data['attributes'] = $attributes instanceof stdClass ? (array) $attributes
                : ($attributes === [] ? [] : null);
        }
        $startRequest = StartRequest::fromJson($data, $configuration->binding->organisationAttribute);
        if ($startRequest === null) {
            return self::respond(['msg' => self::MSG_ERROR], Response::HTTP_BAD_REQUEST);
        }

        $transaction = $this->starter->start($startRequest, $configuration)->transaction;
        if ($transaction === null) {
            return self::respond(['msg' => self::MSG_ERROR], Response::HTTP_OK);
        }

        $body = ['msg' => self::MSG_INTERRUPT, 'nonce' => $transaction->id];
        $message = match ($transaction->state) {
            TransactionState::Pending => self::MESSAGE_LOGIN_REQUIRED,
            TransactionState::Skipped => self::MESSAGE_SKIPPED,
            default => null,
        };
        if ($message !== null) {
            $body['message'] = $message;
        }

        return self::respond($body, Response::HTTP_OK);
    }

    /**
     * @param array<string, string> $body
     */
    private static function respond(array $body, int $status): JsonResponse
    {
        $response = new JsonResponse($body, $status);
        $response->headers->set('Cache-Control', 'no-store');

        return $response;
    }
}
