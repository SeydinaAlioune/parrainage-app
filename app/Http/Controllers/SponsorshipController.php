<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Models\Sponsorship;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Str;
use Spatie\Activitylog\Facades\Activity;

class SponsorshipController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth');
    }

    public function index()
    {
        $sponsorships = Sponsorship::where('voter_id', Auth::id())
            ->with('candidate')
            ->get();
        return view('voter.sponsorships.index', compact('sponsorships'));
    }

    public function create(User $candidate)
    {
        $voter = Auth::user();
        
        if (!$voter->region_id) {
            return redirect()->route('voter.profile')
                ->with('error', 'Vous devez d\'abord sélectionner votre région avant de pouvoir parrainer un candidat.');
        }

        // Vérifier si l'utilisateur a déjà parrainé ce candidat
        $existingSponsorship = Sponsorship::where('voter_id', $voter->id)
            ->where('candidate_id', $candidate->id)
            ->first();

        if ($existingSponsorship) {
            return redirect()->route('voter.sponsorships.index')
                ->with('error', 'Vous avez déjà parrainé ce candidat.');
        }

        if (!Auth::user()->isVoter()) {
            abort(403, 'Seuls les électeurs peuvent parrainer.');
        }

        if (Sponsorship::where('voter_id', Auth::id())->exists()) {
            return redirect()->route('voter.candidates.index')
                ->with('error', 'Vous avez déjà parrainé un candidat.');
        }

        if ($candidate->status !== 'validated') {
            return redirect()->route('voter.candidates.index')
                ->with('error', 'Ce candidat n\'est pas encore validé.');
        }

        return view('voter.sponsorships.create', compact('candidate'));
    }

    public function store(Request $request, User $candidate)
    {
        $voter = Auth::user();

        if (!$voter->region_id) {
            return redirect()->route('voter.profile')
                ->with('error', 'Vous devez d\'abord sélectionner votre région avant de pouvoir parrainer un candidat.');
        }

        // Vérifier si l'utilisateur a déjà parrainé ce candidat
        $existingSponsorship = Sponsorship::where('voter_id', $voter->id)
            ->where('candidate_id', $candidate->id)
            ->first();

        if ($existingSponsorship) {
            return redirect()->route('voter.sponsorships.index')
                ->with('error', 'Vous avez déjà parrainé ce candidat.');
        }

        // Créer le parrainage
        $sponsorship = Sponsorship::create([
            'voter_id' => $voter->id,
            'candidate_id' => $candidate->id,
            'region_id' => $voter->region_id,
            'status' => 'pending'
        ]);

        Activity::causedBy($voter)
            ->performedOn($sponsorship)
            ->log('sponsorship_created');

        return redirect()->route('voter.sponsorships.index')
            ->with('success', 'Votre parrainage a été enregistré avec succès.');
    }

    public function show(Sponsorship $sponsorship)
    {
        if ($sponsorship->voter_id !== Auth::id()) {
            abort(403);
        }

        return view('voter.sponsorships.show', compact('sponsorship'));
    }
}
